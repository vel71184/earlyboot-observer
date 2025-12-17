"""Minimal observer daemon that logs to journald via stdout/stderr."""

from __future__ import annotations

import json
import logging
import random
import signal
import socket
import subprocess
import sys
import struct
import urllib.error
import urllib.request
from threading import Event, Thread

from ebo.checks import Check, Engine, Result

try:
    import dbus
    import dbus.mainloop.glib
    from gi.repository import GLib
except ImportError:
    dbus = None
    GLib = None


_shutdown = Event()
_logger = logging.getLogger("ebo.observer")
_main_loop = None
_check_engine: Engine | None = None
_check_failures_present = False
_bus = None
_last_states: dict[str, tuple[str | None, str | None]] = {}
_systemd_manager = None
_tracked_units: dict[str, str] = {}
_unit_paths: dict[str, str] = {}
_nm_props = None
_nm_connectivity: str | None = None
_nm_active_connections: tuple[str, ...] = ()
_nm_device_ipv4: dict[str, bool] = {}
_nm_ip4_to_device: dict[str, str] = {}
_nm_default_route = False
_nm_net_ready: bool | None = None
_UNIT_NAMES = (
    "NetworkManager.service",
    "ssh.service",
    "tailscaled.service",
    "pihole-FTL.service",
)
_NET_READY_EVENT = "EVENT_NET_READY"
_NET_READY_CHECK = "NET_READY"
_HTTP_DEBIAN_CHECK = "HTTP_OK_DEBIAN"
_DNS_CHECK = "DNS_OK_SYSTEM"
_DNS_QUAD9_CHECK = "DNS_OK_QUAD9"
_DNS_RETRY_INTERVAL_SECONDS = 2
_DNS_MAX_RETRIES = 5
_DNS_DEADLINE_SECONDS = 12
_DNS_ATTEMPT_TIMEOUT_SECONDS = 2
_DNS_QUAD9_SERVER = "9.9.9.9"
_DNS_QUAD9_PORT = 53
_dns_probe_started = False
_dns_attempts_made = 0
_dns_check_resolved = False
_dns_attempt_inflight = False
_quad9_probe_started = False
_quad9_attempts_made = 0
_quad9_check_resolved = False
_quad9_attempt_inflight = False
_HTTP_PROBE_DEADLINE_SECONDS = 10
_HTTP_PROBE_REQUEST_TIMEOUT_SECONDS = 5
_HTTP_PIHOLE_API = "HTTP_PIHOLE_API"
_HTTP_NEXTCLOUD_STATUS = "HTTP_NEXTCLOUD_STATUS"
_HTTP_OLLAMA_TAGS = "HTTP_OLLAMA_TAGS"
_HTTP_FASTAPI_WHISPER_DOCS = "HTTP_FASTAPI_WHISPER_DOCS"
_http_probes: dict[str, dict[str, object]] = {}
_TIME_SYNC_CHECK = "TIME_SYNC_OK"
_TIME_SYNC_DEADLINE_SECONDS = 10
_TIME_SYNC_RETRY_INTERVAL_SECONDS = 3
_TIME_SYNC_MAX_RETRIES = 3
_TIME_SYNC_COMMAND = ("timedatectl", "show", "-p", "NTPSynchronized", "--value")
_time_sync_probe_started = False
_time_sync_attempts_made = 0
_time_sync_check_resolved = False
_time_sync_attempt_inflight = False

NM_BUS_NAME = "org.freedesktop.NetworkManager"
NM_PATH = "/org/freedesktop/NetworkManager"
_CONNECTIVITY_STATES = {
    0: "unknown",
    1: "none",
    2: "portal",
    3: "limited",
    4: "full",
}
RUNTIME_LIMIT_SECONDS = 30


def _init_check_engine(runtime_limit: float) -> None:
    global _check_engine
    _check_engine = Engine(_logger, timeout_seconds=runtime_limit)
    _register_unit_checks(runtime_limit)
    _register_net_ready_check(runtime_limit)
    _register_dns_check(runtime_limit)
    _register_quad9_check(runtime_limit)
    _register_time_sync_check(runtime_limit)
    _register_http_service_checks()
    register_http_probe(
        _HTTP_DEBIAN_CHECK, url="https://deb.debian.org", prerequisites=[_NET_READY_EVENT]
    )


def _register_http_service_checks() -> None:
    register_http_probe(
        _HTTP_PIHOLE_API,
        url="http://127.0.0.1/admin/api.php",
        prerequisites=[_NET_READY_EVENT],
        expected_json=("domains_being_blocked", None),
    )
    register_http_probe(
        _HTTP_NEXTCLOUD_STATUS,
        url="http://127.0.0.1/nextcloud/status.php",
        prerequisites=[_NET_READY_EVENT],
        expected_json=("installed", True),
    )
    register_http_probe(
        _HTTP_OLLAMA_TAGS, url="http://127.0.0.1:11434/api/tags", prerequisites=[_NET_READY_EVENT]
    )
    register_http_probe(
        _HTTP_FASTAPI_WHISPER_DOCS,
        url="http://127.0.0.1:8000/docs",
        prerequisites=[_NET_READY_EVENT],
    )


def _register_unit_checks(runtime_limit: float) -> None:
    if _check_engine is None:
        return
    for unit in _UNIT_NAMES:
        _tracked_units[unit] = unit
        _check_engine.register(Check(unit, deadline_seconds=runtime_limit))


def _register_net_ready_check(runtime_limit: float) -> None:
    if _check_engine is None:
        return
    _check_engine.register(
        Check(_NET_READY_CHECK, prerequisites=[_NET_READY_EVENT], deadline_seconds=runtime_limit)
    )


def _register_dns_check(runtime_limit: float) -> None:
    if _check_engine is None:
        return
    deadline = min(_DNS_DEADLINE_SECONDS, runtime_limit) if runtime_limit else _DNS_DEADLINE_SECONDS
    _check_engine.register(
        Check(_DNS_CHECK, prerequisites=[_NET_READY_EVENT], deadline_seconds=deadline)
    )


def _register_quad9_check(runtime_limit: float) -> None:
    if _check_engine is None:
        return
    deadline = min(_DNS_DEADLINE_SECONDS, runtime_limit) if runtime_limit else _DNS_DEADLINE_SECONDS
    _check_engine.register(
        Check(_DNS_QUAD9_CHECK, prerequisites=[_NET_READY_EVENT], deadline_seconds=deadline)
    )


def _register_time_sync_check(runtime_limit: float) -> None:
    if _check_engine is None:
        return
    deadline = (
        min(_TIME_SYNC_DEADLINE_SECONDS, runtime_limit)
        if runtime_limit
        else _TIME_SYNC_DEADLINE_SECONDS
    )
    _check_engine.register(
        Check(_TIME_SYNC_CHECK, prerequisites=[_NET_READY_EVENT], deadline_seconds=deadline)
    )
    if GLib is None:
        _check_engine.resolve(_TIME_SYNC_CHECK, Result.SKIP, "GLib unavailable for time sync probe")


def register_http_probe(
    name: str,
    url: str = "http://127.0.0.1",
    prerequisites: list[str] | tuple[str, ...] | None = None,
    expected_json: tuple[str, object] | None = None,
    deadline_seconds: float = _HTTP_PROBE_DEADLINE_SECONDS,
) -> None:
    """Register a one-shot HTTP check that runs off the main loop."""
    if _check_engine is None:
        return
    prereqs = list(prerequisites) if prerequisites else []
    deadline = deadline_seconds or 0.0
    if RUNTIME_LIMIT_SECONDS:
        deadline = min(deadline or _HTTP_PROBE_DEADLINE_SECONDS, RUNTIME_LIMIT_SECONDS)
    check = Check(name, prerequisites=prereqs, deadline_seconds=deadline)
    _check_engine.register(check)
    if GLib is None:
        _check_engine.resolve(name, Result.SKIP, "GLib unavailable for HTTP probe")
        return
    _http_probes[name] = {
        "check": check,
        "url": url,
        "expected_json": expected_json,
        "started": False,
        "resolved": False,
    }
    GLib.timeout_add(250, _await_http_probe_arming, name)


def _await_http_probe_arming(name: str) -> bool:
    state = _http_probes.get(name)
    if not state:
        return False
    check = state.get("check")
    if not isinstance(check, Check):
        return False
    if state.get("resolved") or check.result is not None:
        state["resolved"] = True
        return False
    if check.state != "armed":
        return True
    if state.get("started"):
        return False
    state["started"] = True
    Thread(target=_run_http_probe, args=(name,), daemon=True).start()
    return False


def _run_http_probe(name: str) -> None:
    state = _http_probes.get(name)
    if not state:
        return
    url = str(state.get("url", "http://127.0.0.1"))
    expected_json = state.get("expected_json")
    success = False
    reason = f"HTTP probe failed for {url}"
    try:
        request = urllib.request.Request(url, method="GET")
        with urllib.request.urlopen(request, timeout=_HTTP_PROBE_REQUEST_TIMEOUT_SECONDS) as resp:
            status = getattr(resp, "status", resp.getcode())
            body = resp.read()
        success = True
        reason = f"HTTP {status} from {url}"
        if expected_json is not None:
            key, expected_value = expected_json
            try:
                payload = json.loads(body)
            except Exception as exc:
                success = False
                reason = f"HTTP response JSON decode failed: {exc}"
            else:
                if not isinstance(payload, dict):
                    success = False
                    reason = "HTTP response JSON was not an object"
                else:
                    if expected_value is None:
                        if key in payload:
                            reason = f"HTTP {status} JSON contained {key!r}"
                        else:
                            success = False
                            reason = f"expected JSON key {key!r} to exist"
                    else:
                        actual = payload.get(key)
                        if actual != expected_value:
                            success = False
                            reason = f"expected {key!r}={expected_value!r}, got {actual!r}"
                        else:
                            reason = f"HTTP {status} JSON matched {key!r}"
    except urllib.error.HTTPError as exc:
        reason = f"HTTP error {exc.code} for {url}"
    except Exception as exc:
        reason = f"HTTP probe failed for {url}: {exc}"
    if GLib is None:
        if _check_engine is not None:
            _check_engine.resolve(name, Result.FAIL if not success else Result.PASS, reason)
        return
    GLib.idle_add(_complete_http_probe, name, success, reason)


def _complete_http_probe(name: str, success: bool, reason: str) -> bool:
    state = _http_probes.get(name)
    if not state or state.get("resolved"):
        return False
    state["resolved"] = True
    if _check_engine is None:
        return False
    result = Result.PASS if success else Result.FAIL
    _check_engine.resolve(name, result, reason)
    return False


def _finalize_checks() -> None:
    global _check_failures_present
    if _check_engine is None:
        _check_failures_present = False
        return
    if _nm_net_ready is not True:
        _check_engine.resolve(_NET_READY_CHECK, Result.SKIP, "NET_READY not observed")
    _check_engine.enforce_deadlines()
    _check_engine.finalize()
    counts, failed = _check_engine.summary()
    _check_failures_present = bool(failed)
    failed_clause = f" FAILED={','.join(failed)}" if failed else ""
    _logger.info(
        "SUMMARY PASS=%d FAIL=%d SKIP=%d WARN=%d%s",
        counts.get(Result.PASS, 0),
        counts.get(Result.FAIL, 0),
        counts.get(Result.SKIP, 0),
        counts.get(Result.WARN, 0),
        failed_clause,
    )


def _setup_logging() -> None:
    """Send log messages to stdout so systemd can forward them to journald."""
    handler = logging.StreamHandler(sys.stdout)
    formatter = logging.Formatter("%(asctime)s %(levelname)s %(message)s")
    handler.setFormatter(formatter)
    _logger.setLevel(logging.INFO)
    _logger.addHandler(handler)
    _logger.propagate = False


def _handle_signal(signum, _frame) -> None:
    try:
        name = signal.Signals(signum).name
    except ValueError:
        name = str(signum)
    _logger.info("ebo-observer received signal %s; shutting down", name)
    _shutdown.set()
    _stop_main_loop()


def _stop_main_loop() -> None:
    if _main_loop is not None and _main_loop.is_running():
        _main_loop.quit()


def _resolve_unit_id(path: str) -> str:
    if not _bus or not dbus:
        return path
    try:
        unit = _bus.get_object("org.freedesktop.systemd1", path)
        props = dbus.Interface(unit, dbus_interface="org.freedesktop.DBus.Properties")
        unit_id = props.Get("org.freedesktop.systemd1.Unit", "Id")
        return str(unit_id)
    except Exception as exc:  # pragma: no cover - best-effort logging path
        _logger.debug("Could not resolve unit id for %s: %s", path, exc)
        return path


def _get_systemd_manager():
    global _systemd_manager
    if dbus is None or _bus is None:
        return None
    if _systemd_manager is None:
        try:
            manager_obj = _bus.get_object("org.freedesktop.systemd1", "/org/freedesktop/systemd1")
            _systemd_manager = dbus.Interface(
                manager_obj, dbus_interface="org.freedesktop.systemd1.Manager"
            )
        except Exception as exc:
            _logger.info("systemd manager unavailable: %s", exc)
            return None
    return _systemd_manager


def _log_state_change(unit: str, active, sub) -> None:
    active_text = f"ActiveState={active}" if active is not None else None
    sub_text = f"SubState={sub}" if sub is not None else None
    details = " ".join(part for part in (active_text, sub_text) if part)
    _logger.info("unit %s state changed %s", unit, details)
    if str(active) == "failed" or str(sub) == "failed":
        _logger.error("unit %s entered failed state", unit)


def _get_systemd_properties_interface(path: str):
    if not dbus or not _bus:
        return None
    try:
        proxy = _bus.get_object("org.freedesktop.systemd1", path)
        return dbus.Interface(proxy, dbus_interface="org.freedesktop.DBus.Properties")
    except Exception as exc:  # pragma: no cover - best-effort logging path
        _logger.debug("Could not get systemd properties for %s: %s", path, exc)
        return None


def _resolve_unit_check(unit: str, active_state: str | None) -> None:
    if _check_engine is None or unit not in _tracked_units:
        return
    if active_state == "active":
        _check_engine.resolve(unit, Result.PASS, "unit active")
    elif active_state == "failed":
        _check_engine.resolve(unit, Result.FAIL, "unit failed")


def _update_unit_state(unit: str, active, sub) -> None:
    prev_active, prev_sub = _last_states.get(unit, (None, None))
    current_active = str(active) if active is not None else prev_active
    current_sub = str(sub) if sub is not None else prev_sub
    if (current_active, current_sub) == (prev_active, prev_sub):
        return
    _last_states[unit] = (current_active, current_sub)
    _log_state_change(unit, current_active, current_sub)
    _resolve_unit_check(unit, current_active)


def _is_no_such_unit(exc: Exception) -> bool:
    dbus_name = getattr(exc, "get_dbus_name", lambda: "")()
    return str(dbus_name) == "org.freedesktop.systemd1.NoSuchUnit"


def _load_unit(unit_name: str, manager=None) -> tuple[str | None, bool]:
    manager = manager or _get_systemd_manager()
    if not manager:
        return None, False
    try:
        unit_path = manager.LoadUnit(unit_name)
        return str(unit_path), False
    except Exception as exc:
        if _is_no_such_unit(exc):
            _logger.info("unit %s not found", unit_name)
            return None, True
        _logger.debug("Could not load unit %s: %s", unit_name, exc)
    return None, False


def _prime_unit_state(unit_name: str, unit_path: str) -> None:
    props = _get_systemd_properties_interface(unit_path)
    if not props:
        return
    try:
        active = props.Get("org.freedesktop.systemd1.Unit", "ActiveState")
        sub = props.Get("org.freedesktop.systemd1.Unit", "SubState")
    except Exception as exc:
        _logger.debug("Could not read initial state for %s: %s", unit_name, exc)
        return
    _update_unit_state(unit_name, active, sub)


def _track_unit(unit_name: str, manager=None) -> None:
    if _check_engine is None:
        return
    path, missing = _load_unit(unit_name, manager=manager)
    if not path:
        if missing:
            _check_engine.resolve(unit_name, Result.SKIP, "unit not found")
        return
    path = str(path)
    _unit_paths[path] = unit_name
    _prime_unit_state(unit_name, path)


def _init_systemd_units() -> None:
    manager = _get_systemd_manager()
    if _check_engine is None or not manager:
        return
    for unit in _UNIT_NAMES:
        _track_unit(unit, manager)


def _on_properties_changed(interface, changed, _invalidated, path=None, **_kwargs) -> None:
    if interface != "org.freedesktop.systemd1.Unit":
        return
    active = changed.get("ActiveState")
    sub = changed.get("SubState")
    if active is None and sub is None:
        return
    unit_path = str(path or "")
    unit = _unit_paths.get(unit_path) or _resolve_unit_id(unit_path)
    if unit not in _tracked_units:
        return
    _update_unit_state(unit, active, sub)


def _on_job_removed(_job_id, _job_path, unit, result, **_kwargs) -> None:
    if str(result) != "failed":
        return
    _logger.error("job for unit %s failed", unit)


def _register_systemd_signal_listeners() -> None:
    assert dbus is not None
    assert _bus is not None
    _bus.add_signal_receiver(
        _on_properties_changed,
        signal_name="PropertiesChanged",
        dbus_interface="org.freedesktop.DBus.Properties",
        path_keyword="path",
    )
    _bus.add_signal_receiver(
        _on_job_removed,
        signal_name="JobRemoved",
        dbus_interface="org.freedesktop.systemd1.Manager",
        bus_name="org.freedesktop.systemd1",
    )


def _get_properties_interface(path: str):
    if not dbus or not _bus:
        return None
    try:
        proxy = _bus.get_object(NM_BUS_NAME, path)
        return dbus.Interface(proxy, dbus_interface="org.freedesktop.DBus.Properties")
    except Exception as exc:  # pragma: no cover - runtime guard
        _logger.debug("Could not get properties for %s: %s", path, exc)
        return None


def _connectivity_label(raw) -> str:
    try:
        numeric = int(raw)
    except Exception:
        return str(raw)
    return _CONNECTIVITY_STATES.get(numeric, str(numeric))


def _ip4_config_has_addresses(ip4_path: str) -> bool:
    props = _get_properties_interface(ip4_path)
    if not props:
        return False
    try:
        address_data = props.Get("org.freedesktop.NetworkManager.IP4Config", "AddressData")
        if address_data:
            return any(bool(entry.get("address")) for entry in address_data)
    except Exception as exc:
        _logger.debug("Could not read IPv4 addresses for %s: %s", ip4_path, exc)
    return False


def _ip4_config_has_default_route(ip4_path: str) -> bool:
    props = _get_properties_interface(ip4_path)
    if not props:
        return False
    try:
        gateway = props.Get("org.freedesktop.NetworkManager.IP4Config", "Gateway")
        if gateway:
            return True
    except Exception as exc:
        _logger.debug("Could not read IPv4 gateway for %s: %s", ip4_path, exc)
    try:
        route_data = props.Get("org.freedesktop.NetworkManager.IP4Config", "RouteData")
        for route in route_data:
            if str(route.get("dest", "")) in ("0.0.0.0", "") and int(route.get("prefix", 32)) == 0:
                return True
    except Exception:
        pass
    try:
        routes = props.Get("org.freedesktop.NetworkManager.IP4Config", "Routes")
        for route in routes:
            try:
                dest, prefix, _gateway, _metric = route
            except Exception:
                continue
            if int(prefix) == 0 or str(dest) == "0.0.0.0":
                return True
    except Exception as exc:
        _logger.debug("Could not read IPv4 routes for %s: %s", ip4_path, exc)
    return False


def _update_device_state(device_path: str) -> None:
    props = _get_properties_interface(device_path)
    if not props:
        return
    ip4_path = None
    try:
        ip4_path = props.Get("org.freedesktop.NetworkManager.Device", "Ip4Config")
        ip4_path = str(ip4_path)
    except Exception as exc:
        _logger.debug("Could not read Ip4Config for %s: %s", device_path, exc)
    for known_ip4, mapped_device in list(_nm_ip4_to_device.items()):
        if mapped_device == device_path and known_ip4 != ip4_path:
            _nm_ip4_to_device.pop(known_ip4, None)
    if ip4_path and ip4_path != "/":
        _nm_ip4_to_device[ip4_path] = device_path
    has_ipv4 = _ip4_config_has_addresses(ip4_path) if ip4_path and ip4_path != "/" else False
    previous = _nm_device_ipv4.get(device_path)
    _nm_device_ipv4[device_path] = has_ipv4
    if previous != has_ipv4:
        _logger.info("device %s IPv4 assigned=%s", device_path, has_ipv4)
    _recompute_net_ready()


def _refresh_device_list() -> None:
    if not dbus or not _bus:
        return
    try:
        nm_iface = dbus.Interface(
            _bus.get_object(NM_BUS_NAME, NM_PATH),
            dbus_interface="org.freedesktop.NetworkManager",
        )
        devices = [str(path) for path in nm_iface.GetDevices()]
    except Exception as exc:
        _logger.debug("Could not fetch NetworkManager devices: %s", exc)
        return
    for device_path in devices:
        _update_device_state(device_path)
    for known_device in list(_nm_device_ipv4):
        if known_device not in devices:
            _nm_device_ipv4.pop(known_device, None)
    _recompute_net_ready()


def _describe_active_connection(path: str) -> str:
    props = _get_properties_interface(path)
    if not props:
        return path
    try:
        name = props.Get("org.freedesktop.NetworkManager.Connection.Active", "Id")
        if name:
            return str(name)
    except Exception as exc:
        _logger.debug("Could not read connection id for %s: %s", path, exc)
    return path


def _active_connection_has_default_route(path: str) -> bool:
    props = _get_properties_interface(path)
    if not props:
        return False
    try:
        if bool(props.Get("org.freedesktop.NetworkManager.Connection.Active", "Default")):
            return True
    except Exception as exc:
        _logger.debug("Could not read Default flag for %s: %s", path, exc)
    try:
        ip4_path = props.Get("org.freedesktop.NetworkManager.Connection.Active", "Ip4Config")
        ip4_path = str(ip4_path)
        if ip4_path and ip4_path != "/" and _ip4_config_has_default_route(ip4_path):
            return True
    except Exception as exc:
        _logger.debug("Could not read Ip4Config for %s: %s", path, exc)
    return False


def _update_default_route(active_paths: tuple[str, ...]) -> None:
    global _nm_default_route
    has_default = False
    for path in active_paths:
        if _active_connection_has_default_route(path):
            has_default = True
            break
    if has_default != _nm_default_route:
        _nm_default_route = has_default
        _logger.info("NetworkManager default route present=%s", has_default)
    _recompute_net_ready()


def _handle_active_connections_changed(active_paths) -> None:
    global _nm_active_connections
    normalized = tuple(str(path) for path in active_paths)
    if normalized == _nm_active_connections:
        return
    names = ", ".join(_describe_active_connection(path) for path in normalized) or "none"
    _nm_active_connections = normalized
    _logger.info("NetworkManager active connections changed: %s", names)
    _update_default_route(normalized)


def _update_nm_connectivity(raw) -> None:
    global _nm_connectivity
    label = _connectivity_label(raw)
    if label == _nm_connectivity:
        return
    _nm_connectivity = label
    _logger.info("NetworkManager connectivity %s", label)
    _recompute_net_ready()


def _on_net_ready() -> None:
    if _check_engine is None:
        return
    _check_engine.emit_event(_NET_READY_EVENT)
    _check_engine.resolve(_NET_READY_CHECK, Result.PASS, "network ready")
    _start_dns_probe()
    _start_quad9_probe()
    _start_time_sync_probe()


def _start_dns_probe() -> None:
    global _dns_probe_started, _dns_attempts_made, _dns_check_resolved, _dns_attempt_inflight
    if _check_engine is None or GLib is None:
        return
    if _dns_probe_started:
        return
    _dns_probe_started = True
    _dns_attempts_made = 0
    _dns_check_resolved = False
    _dns_attempt_inflight = False
    _schedule_dns_attempt(0)


def _schedule_dns_attempt(delay_seconds: int) -> None:
    if _dns_check_resolved or GLib is None:
        return
    GLib.timeout_add_seconds(delay_seconds, _spawn_dns_attempt_thread)


def _spawn_dns_attempt_thread() -> bool:
    global _dns_attempt_inflight
    if _dns_check_resolved:
        return False
    if _dns_attempt_inflight:
        return False
    _dns_attempt_inflight = True
    Thread(target=_run_dns_attempt, daemon=True).start()
    return False


def _run_dns_attempt() -> None:
    global _dns_attempts_made
    _dns_attempts_made += 1
    attempt_number = _dns_attempts_made
    success = _perform_dns_lookup()
    if GLib is None:
        return
    GLib.idle_add(_handle_dns_attempt_result, success, attempt_number)


def _perform_dns_lookup() -> bool:
    try:
        result = subprocess.run(
            ["getent", "hosts", "debian.org"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=_DNS_ATTEMPT_TIMEOUT_SECONDS,
            check=False,
        )
        if result.returncode == 0:
            return True
    except Exception as exc:
        _logger.debug("DNS getent failed: %s", exc)
    try:
        socket.getaddrinfo("debian.org", None)
        return True
    except Exception as exc:
        _logger.debug("DNS getaddrinfo failed: %s", exc)
    return False


def _handle_dns_attempt_result(success: bool, attempt_number: int) -> bool:
    global _dns_attempt_inflight
    _dns_attempt_inflight = False
    if _dns_check_resolved:
        return False
    if success:
        _resolve_dns_check(Result.PASS, f"resolved debian.org on attempt {attempt_number}")
        return False
    if _dns_attempts_made > _DNS_MAX_RETRIES:
        attempts_total = _dns_attempts_made
        _resolve_dns_check(Result.FAIL, f"DNS resolution failed after {attempts_total} attempts")
        return False
    _schedule_dns_attempt(_DNS_RETRY_INTERVAL_SECONDS)
    return False


def _resolve_dns_check(result: Result, reason: str) -> None:
    global _dns_check_resolved
    if _dns_check_resolved or _check_engine is None:
        return
    _dns_check_resolved = True
    _check_engine.resolve(_DNS_CHECK, result, reason)


def _start_quad9_probe() -> None:
    global _quad9_probe_started, _quad9_attempts_made, _quad9_check_resolved, _quad9_attempt_inflight
    if _check_engine is None or GLib is None:
        return
    if _quad9_probe_started:
        return
    _quad9_probe_started = True
    _quad9_attempts_made = 0
    _quad9_check_resolved = False
    _quad9_attempt_inflight = False
    _schedule_quad9_attempt(0)


def _schedule_quad9_attempt(delay_seconds: int) -> None:
    if _quad9_check_resolved or GLib is None:
        return
    GLib.timeout_add_seconds(delay_seconds, _spawn_quad9_attempt_thread)


def _spawn_quad9_attempt_thread() -> bool:
    global _quad9_attempt_inflight
    if _quad9_check_resolved or _quad9_attempt_inflight:
        return False
    _quad9_attempt_inflight = True
    Thread(target=_run_quad9_attempt, daemon=True).start()
    return False


def _run_quad9_attempt() -> None:
    global _quad9_attempts_made
    _quad9_attempts_made += 1
    attempt_number = _quad9_attempts_made
    success = _perform_quad9_lookup()
    if GLib is None:
        return
    GLib.idle_add(_handle_quad9_attempt_result, success, attempt_number)


def _build_dns_query(hostname: str) -> tuple[int, bytes]:
    transaction_id = random.randint(0, 0xFFFF)
    labels = hostname.split(".")
    question = b"".join(bytes((len(label),)) + label.encode("ascii") for label in labels) + b"\x00"
    question += struct.pack("!HH", 1, 1)  # QTYPE=A, QCLASS=IN
    header = struct.pack("!HHHHHH", transaction_id, 0x0100, 1, 0, 0, 0)
    return transaction_id, header + question


def _perform_quad9_lookup() -> bool:
    transaction_id, query = _build_dns_query("debian.org")
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(_DNS_ATTEMPT_TIMEOUT_SECONDS)
            sock.sendto(query, (_DNS_QUAD9_SERVER, _DNS_QUAD9_PORT))
            response, _addr = sock.recvfrom(512)
    except Exception as exc:
        _logger.debug("Quad9 DNS query failed: %s", exc)
        return False
    if len(response) < 12:
        return False
    try:
        resp_id, flags, _qdcount, ancount, _nscount, _arcount = struct.unpack(
            "!HHHHHH", response[:12]
        )
    except Exception as exc:
        _logger.debug("Quad9 DNS response parse failed: %s", exc)
        return False
    if resp_id != transaction_id:
        return False
    rcode = flags & 0x000F
    if rcode != 0:
        return False
    return ancount > 0


def _handle_quad9_attempt_result(success: bool, attempt_number: int) -> bool:
    global _quad9_attempt_inflight
    _quad9_attempt_inflight = False
    if _quad9_check_resolved:
        return False
    if success:
        _resolve_quad9_check(
            Result.PASS, f"resolved debian.org via Quad9 on attempt {attempt_number}"
        )
        return False
    if _quad9_attempts_made > _DNS_MAX_RETRIES:
        attempts_total = _quad9_attempts_made
        _resolve_quad9_check(
            Result.FAIL, f"Quad9 DNS resolution failed after {attempts_total} attempts"
        )
        return False
    _schedule_quad9_attempt(_DNS_RETRY_INTERVAL_SECONDS)
    return False


def _resolve_quad9_check(result: Result, reason: str) -> None:
    global _quad9_check_resolved
    if _quad9_check_resolved or _check_engine is None:
        return
    _quad9_check_resolved = True
    _check_engine.resolve(_DNS_QUAD9_CHECK, result, reason)


def _start_time_sync_probe() -> None:
    global _time_sync_probe_started, _time_sync_attempts_made, _time_sync_check_resolved
    global _time_sync_attempt_inflight
    if _check_engine is None or GLib is None:
        return
    if _time_sync_probe_started:
        return
    _time_sync_probe_started = True
    _time_sync_attempts_made = 0
    _time_sync_check_resolved = False
    _time_sync_attempt_inflight = False
    _schedule_time_sync_attempt(0)


def _schedule_time_sync_attempt(delay_seconds: int) -> None:
    if _time_sync_check_resolved or GLib is None:
        return
    GLib.timeout_add_seconds(delay_seconds, _spawn_time_sync_attempt_thread)


def _spawn_time_sync_attempt_thread() -> bool:
    global _time_sync_attempt_inflight
    if _time_sync_check_resolved or _time_sync_attempt_inflight:
        return False
    _time_sync_attempt_inflight = True
    Thread(target=_run_time_sync_attempt, daemon=True).start()
    return False


def _run_time_sync_attempt() -> None:
    global _time_sync_attempts_made
    _time_sync_attempts_made += 1
    attempt_number = _time_sync_attempts_made
    synced = _probe_time_sync()
    if GLib is None:
        return
    GLib.idle_add(_handle_time_sync_attempt_result, synced, attempt_number)


def _probe_time_sync() -> bool:
    try:
        result = subprocess.run(
            _TIME_SYNC_COMMAND,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=5,
        )
    except Exception as exc:
        _logger.debug("timedatectl NTPSynchronized check failed: %s", exc)
        return False
    output = (result.stdout or "").strip().lower()
    return output == "yes"


def _handle_time_sync_attempt_result(synced: bool, attempt_number: int) -> bool:
    global _time_sync_attempt_inflight
    _time_sync_attempt_inflight = False
    if _time_sync_check_resolved:
        return False
    if synced:
        _resolve_time_sync_check(Result.PASS, f"NTPSynchronized=yes on attempt {attempt_number}")
        return False
    if _time_sync_attempts_made > _TIME_SYNC_MAX_RETRIES:
        attempts_total = _time_sync_attempts_made
        _resolve_time_sync_check(
            Result.FAIL, f"NTPSynchronized not reported after {attempts_total} attempts"
        )
        return False
    _schedule_time_sync_attempt(_TIME_SYNC_RETRY_INTERVAL_SECONDS)
    return False


def _resolve_time_sync_check(result: Result, reason: str) -> None:
    global _time_sync_check_resolved
    if _time_sync_check_resolved or _check_engine is None:
        return
    _time_sync_check_resolved = True
    _check_engine.resolve(_TIME_SYNC_CHECK, result, reason)


def _recompute_net_ready() -> None:
    global _nm_net_ready
    has_ipv4 = any(_nm_device_ipv4.values())
    connectivity_ok = _nm_connectivity in ("full", "limited")
    net_ready = connectivity_ok and (has_ipv4 or _nm_default_route)
    if net_ready == _nm_net_ready:
        return
    _nm_net_ready = net_ready
    _logger.info("NET_READY=%s", net_ready)
    if net_ready:
        _on_net_ready()


def _prime_network_manager_state() -> None:
    if not _nm_props:
        return
    try:
        connectivity = _nm_props.Get("org.freedesktop.NetworkManager", "Connectivity")
        _update_nm_connectivity(connectivity)
    except Exception as exc:
        _logger.debug("Could not read initial connectivity: %s", exc)
    try:
        active_connections = _nm_props.Get("org.freedesktop.NetworkManager", "ActiveConnections")
        _handle_active_connections_changed(active_connections)
    except Exception as exc:
        _logger.debug("Could not read initial active connections: %s", exc)
    _refresh_device_list()


def _on_nm_properties_changed(interface, changed, _invalidated, path=None, **_kwargs) -> None:
    if interface != "org.freedesktop.NetworkManager":
        return
    if "Connectivity" in changed:
        _update_nm_connectivity(changed.get("Connectivity"))
    if "ActiveConnections" in changed:
        _handle_active_connections_changed(changed.get("ActiveConnections") or ())


def _on_nm_state_changed(state, **_kwargs) -> None:
    _logger.info("NetworkManager state changed to %s", state)


def _on_nm_device_added(device_path, **_kwargs) -> None:
    device_path = str(device_path)
    _logger.info("NetworkManager device added %s", device_path)
    _update_device_state(device_path)


def _on_nm_device_removed(device_path, **_kwargs) -> None:
    device_path = str(device_path)
    _logger.info("NetworkManager device removed %s", device_path)
    _nm_device_ipv4.pop(device_path, None)
    for ip4_path, mapped_device in list(_nm_ip4_to_device.items()):
        if mapped_device == device_path:
            _nm_ip4_to_device.pop(ip4_path, None)
    _update_default_route(_nm_active_connections)
    _recompute_net_ready()


def _on_nm_device_properties_changed(interface, _changed, _invalidated, path=None, **_kwargs) -> None:
    if not interface.startswith("org.freedesktop.NetworkManager.Device"):
        return
    if path:
        _update_device_state(str(path))
        _update_default_route(_nm_active_connections)


def _on_nm_active_connection_properties_changed(interface, changed, _invalidated, path=None, **_kwargs) -> None:
    if interface != "org.freedesktop.NetworkManager.Connection.Active":
        return
    if "Default" in changed or "Ip4Config" in changed:
        _update_default_route(_nm_active_connections)
    if "Id" in changed:
        _handle_active_connections_changed(_nm_active_connections)


def _on_nm_ip4config_properties_changed(interface, _changed, _invalidated, path=None, **_kwargs) -> None:
    if interface != "org.freedesktop.NetworkManager.IP4Config" or not path:
        return
    device_path = _nm_ip4_to_device.get(str(path))
    if device_path:
        _update_device_state(device_path)
        _update_default_route(_nm_active_connections)


def _register_network_manager_signal_listeners() -> None:
    assert dbus is not None
    assert _bus is not None
    _bus.add_signal_receiver(
        _on_nm_properties_changed,
        signal_name="PropertiesChanged",
        dbus_interface="org.freedesktop.DBus.Properties",
        bus_name=NM_BUS_NAME,
        path=NM_PATH,
        arg0="org.freedesktop.NetworkManager",
        path_keyword="path",
    )
    _bus.add_signal_receiver(
        _on_nm_state_changed,
        signal_name="StateChanged",
        dbus_interface="org.freedesktop.NetworkManager",
        bus_name=NM_BUS_NAME,
    )
    _bus.add_signal_receiver(
        _on_nm_device_added,
        signal_name="DeviceAdded",
        dbus_interface="org.freedesktop.NetworkManager",
        bus_name=NM_BUS_NAME,
    )
    _bus.add_signal_receiver(
        _on_nm_device_removed,
        signal_name="DeviceRemoved",
        dbus_interface="org.freedesktop.NetworkManager",
        bus_name=NM_BUS_NAME,
    )
    _bus.add_signal_receiver(
        _on_nm_device_properties_changed,
        signal_name="PropertiesChanged",
        dbus_interface="org.freedesktop.DBus.Properties",
        bus_name=NM_BUS_NAME,
        path_keyword="path",
    )
    _bus.add_signal_receiver(
        _on_nm_active_connection_properties_changed,
        signal_name="PropertiesChanged",
        dbus_interface="org.freedesktop.DBus.Properties",
        bus_name=NM_BUS_NAME,
        arg0="org.freedesktop.NetworkManager.Connection.Active",
        path_keyword="path",
    )
    _bus.add_signal_receiver(
        _on_nm_ip4config_properties_changed,
        signal_name="PropertiesChanged",
        dbus_interface="org.freedesktop.DBus.Properties",
        bus_name=NM_BUS_NAME,
        arg0="org.freedesktop.NetworkManager.IP4Config",
        path_keyword="path",
    )


def _init_network_manager() -> None:
    global _nm_props
    if dbus is None or _bus is None:
        return
    try:
        nm_obj = _bus.get_object(NM_BUS_NAME, NM_PATH)
        _nm_props = dbus.Interface(nm_obj, dbus_interface="org.freedesktop.DBus.Properties")
    except Exception as exc:
        _logger.info("NetworkManager not available: %s", exc)
        return
    _register_network_manager_signal_listeners()
    _prime_network_manager_state()


def _register_signal_listeners() -> None:
    assert dbus is not None
    assert _bus is not None
    _register_systemd_signal_listeners()
    _init_network_manager()


def _connect_dbus() -> bool:
    global _bus, _main_loop
    if dbus is None or GLib is None:
        _logger.error("D-Bus support unavailable; install dbus-python and pygobject")
        return False
    dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)
    try:
        _bus = dbus.SystemBus()
    except Exception as exc:
        _logger.error("Failed to connect to system D-Bus: %s", exc)
        return False
    _register_signal_listeners()
    _main_loop = GLib.MainLoop()
    return True


def _timeout_shutdown() -> bool:
    _logger.info("ebo-observer reached runtime limit; shutting down")
    _shutdown.set()
    _stop_main_loop()
    return False


def main() -> int:
    _setup_logging()
    _init_check_engine(RUNTIME_LIMIT_SECONDS)
    signal.signal(signal.SIGTERM, _handle_signal)
    signal.signal(signal.SIGINT, _handle_signal)

    _logger.info("ebo-observer starting up")
    if _connect_dbus():
        _init_systemd_units()
        GLib.timeout_add_seconds(RUNTIME_LIMIT_SECONDS, _timeout_shutdown)
        _main_loop.run()
    else:
        _shutdown.wait(timeout=RUNTIME_LIMIT_SECONDS)
    _finalize_checks()
    _logger.info("ebo-observer shutting down")
    return 1 if _check_failures_present else 0


if __name__ == "__main__":
    sys.exit(main())

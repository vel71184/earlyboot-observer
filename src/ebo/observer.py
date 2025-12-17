"""Minimal observer daemon that logs to journald via stdout/stderr."""

from __future__ import annotations

import logging
import signal
import socket
import subprocess
import sys
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
_DNS_CHECK = "DNS_OK_SYSTEM"
_DNS_RETRY_INTERVAL_SECONDS = 2
_DNS_MAX_RETRIES = 5
_DNS_DEADLINE_SECONDS = 12
_DNS_ATTEMPT_TIMEOUT_SECONDS = 2
_dns_probe_started = False
_dns_attempts_made = 0
_dns_check_resolved = False
_dns_attempt_inflight = False

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


def _finalize_checks() -> None:
    if _check_engine is None:
        return
    if _nm_net_ready is not True:
        _check_engine.resolve(_NET_READY_CHECK, Result.SKIP, "NET_READY not observed")
    _check_engine.enforce_deadlines()
    _check_engine.finalize()


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
    return 0


if __name__ == "__main__":
    sys.exit(main())

"""Minimal observer daemon that logs to journald via stdout/stderr."""

from __future__ import annotations

import logging
import signal
import sys
from threading import Event

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
_bus = None
_last_states: dict[str, tuple[str | None, str | None]] = {}


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


def _log_state_change(unit: str, active, sub) -> None:
    active_text = f"ActiveState={active}" if active is not None else None
    sub_text = f"SubState={sub}" if sub is not None else None
    details = " ".join(part for part in (active_text, sub_text) if part)
    _logger.info("unit %s state changed %s", unit, details)
    if str(active) == "failed" or str(sub) == "failed":
        _logger.error("unit %s entered failed state", unit)


def _on_properties_changed(interface, changed, _invalidated, path=None, **_kwargs) -> None:
    if interface != "org.freedesktop.systemd1.Unit":
        return
    active = changed.get("ActiveState")
    sub = changed.get("SubState")
    if active is None and sub is None:
        return
    unit = _resolve_unit_id(path or "")
    prev_active, prev_sub = _last_states.get(unit, (None, None))
    current_active = str(active) if active is not None else prev_active
    current_sub = str(sub) if sub is not None else prev_sub
    if (current_active, current_sub) == (prev_active, prev_sub):
        return
    _last_states[unit] = (current_active, current_sub)
    _log_state_change(unit, current_active, current_sub)


def _on_job_removed(_job_id, _job_path, unit, result, **_kwargs) -> None:
    if str(result) != "failed":
        return
    _logger.error("job for unit %s failed", unit)


def _register_signal_listeners() -> None:
    assert dbus is not None
    assert _bus is not None
    _bus.add_signal_receiver(
        _on_properties_changed,
        signal_name="PropertiesChanged",
        dbus_interface="org.freedesktop.DBus.Properties",
        bus_name="org.freedesktop.systemd1",
        path_keyword="path",
        arg0="org.freedesktop.systemd1.Unit",
    )
    _bus.add_signal_receiver(
        _on_job_removed,
        signal_name="JobRemoved",
        dbus_interface="org.freedesktop.systemd1.Manager",
        bus_name="org.freedesktop.systemd1",
    )


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
    signal.signal(signal.SIGTERM, _handle_signal)
    signal.signal(signal.SIGINT, _handle_signal)

    _logger.info("ebo-observer starting up")
    if _connect_dbus():
        GLib.timeout_add_seconds(30, _timeout_shutdown)
        _main_loop.run()
    else:
        _shutdown.wait(timeout=30)
    _logger.info("ebo-observer shutting down")
    return 0


if __name__ == "__main__":
    sys.exit(main())

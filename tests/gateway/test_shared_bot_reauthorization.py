"""Regression coverage for credentialless shared-bot satellites.

These tests deliberately avoid importing ``gateway.run``: this source checkout's
runtime bootstrap reads the real Hermes install manifest, which the test guard
forbids. The behaviors here are pure routing/binding decisions.
"""

from types import SimpleNamespace

from gateway.config import Platform
from gateway.profile_routing import parse_profile_routes
from gateway.session import SessionSource


def _satellite_source():
    return SessionSource(
        platform=Platform.DISCORD,
        chat_id="THREAD",
        chat_type="thread",
        user_id="USER",
        thread_id="THREAD",
        parent_chat_id="PARENT",
        scope_id="GUILD",
        profile="developer",
    )


def test_saved_shared_bot_source_binds_primary_adapter(tmp_path, monkeypatch):
    from gateway import session_ingress_context as ingress

    home = tmp_path / "default"
    satellite = tmp_path / "developer"
    home.mkdir()
    satellite.mkdir()
    primary = SimpleNamespace(label="PRIMARY")
    runner = SimpleNamespace(
        adapters={Platform.DISCORD: primary},
        _profile_adapters={"developer": {}},
        _native_transport_homes={None: home, "developer": satellite},
        config=SimpleNamespace(
            multiplex_profiles=True,
            profile_routes=parse_profile_routes([{
                "platform": "discord",
                "guild_id": "GUILD",
                "chat_id": "PARENT",
                "profile": "developer",
            }]),
            _runtime_profile_homes=[("default", home), ("developer", satellite)],
        ),
        _is_shared_bot_satellite=lambda profile: profile == "developer",
        _adapter_credential_fingerprint=lambda adapter: f"fp-{adapter.label}",
    )
    monkeypatch.setattr(
        "gateway.session_authorities.authority_for_home", lambda *_args: object(),
    )
    monkeypatch.setattr(
        "hermes_constants.get_process_hermes_home", lambda: home,
    )

    adapter, bound_home, runtime_home, provenance = ingress._binding(runner, _satellite_source(), None)

    assert adapter is primary
    assert bound_home == home.resolve()
    assert runtime_home == satellite.resolve()
    assert provenance["connector"] == "fp-PRIMARY"


def test_parent_channel_route_authorizes_only_its_thread():
    from cron.scheduler_preflight import SharedRouteAdapters

    primary = object()
    routes = parse_profile_routes([{
        "platform": "discord",
        "guild_id": "GUILD",
        "chat_id": "PARENT",
        "profile": "developer",
    }])
    shared = SharedRouteAdapters({Platform.DISCORD: primary}, routes)
    target = {
        "platform": "discord",
        "chat_id": "THREAD",
        "thread_id": "THREAD",
        "parent_chat_id": "PARENT",
        "guild_id": "GUILD",
    }

    assert shared.get(Platform.DISCORD, target) is primary
    assert shared.get(Platform.DISCORD, {**target, "parent_chat_id": "OTHER"}) is None
    assert shared.get(Platform.DISCORD) is None


def test_origin_thread_keeps_parent_for_shared_route_authorization():
    from cron.scheduler_delivery import _resolve_delivery_targets
    from cron.scheduler_preflight import SharedRouteAdapters

    primary = object()
    routes = parse_profile_routes([{
        "platform": "discord", "guild_id": "GUILD", "chat_id": "PARENT", "profile": "developer",
    }])
    job = {
        "id": "job",
        "deliver": "origin",
        "origin": {
            "platform": "discord",
            "chat_id": "THREAD",
            "thread_id": "THREAD",
            "parent_chat_id": "PARENT",
        },
    }
    target = _resolve_delivery_targets(job)[0]
    assert SharedRouteAdapters({Platform.DISCORD: primary}, routes).get(Platform.DISCORD, target) is primary


def test_restored_satellite_source_uses_primary_adapter(tmp_path, monkeypatch):
    import sys
    from types import ModuleType

    fake_run = ModuleType("gateway.run")
    fake_run._multiplex_profile_homes = lambda config: list(config._runtime_profile_homes)
    monkeypatch.setitem(sys.modules, "gateway.run", fake_run)
    from gateway.authz_mixin import GatewayAuthorizationMixin

    home = tmp_path / "default"
    satellite = home / "profiles" / "developer"
    satellite.mkdir(parents=True)
    primary = object()
    runner = object.__new__(GatewayAuthorizationMixin)
    runner.adapters = {Platform.DISCORD: primary}
    runner._profile_adapters = {"developer": {}}
    runner._profile_failed_platforms = {}
    runner._primary_profile_name = "default"
    runner.config = SimpleNamespace(
        multiplex_profiles=True,
        profile_routes=parse_profile_routes([{
            "platform": "discord", "guild_id": "GUILD", "chat_id": "PARENT", "profile": "developer",
        }]),
        _runtime_profile_homes=[("default", home), ("developer", satellite)],
    )
    assert runner._delivery_adapter_for(_satellite_source()) is primary


def test_recovery_accepts_shared_adapter_when_origin_lookup_is_empty(tmp_path, monkeypatch):
    """Startup recovery passes the origin lookup. A restored shared-bot source can still
    resolve the connected primary adapter; an empty lookup must not pause the conversation."""
    import asyncio
    import sys
    from types import ModuleType

    fake_run = ModuleType("gateway.run")
    fake_run._multiplex_profile_homes = lambda config: list(config._runtime_profile_homes)
    monkeypatch.setitem(sys.modules, "gateway.run", fake_run)
    from gateway.authz_mixin import GatewayAuthorizationMixin
    from gateway.session_envelope import check_native_route
    from hermes_state_runtime import RuntimeStoreError

    home = tmp_path / "default"
    satellite = home / "profiles" / "developer"
    satellite.mkdir(parents=True)
    monkeypatch.setattr("hermes_constants.get_process_hermes_home", lambda: home)
    monkeypatch.setattr("gateway.session_authorities.authority_for_home", lambda *_args: object())

    class Adapter:
        label = "PRIMARY"

    primary = Adapter()
    runner = object.__new__(GatewayAuthorizationMixin)
    runner.adapters = {Platform.DISCORD: primary}
    runner._profile_adapters = {"developer": {}}
    runner._native_transport_homes = {None: home}
    runner._adapter_credential_fingerprint = lambda _adapter: "fingerprint"
    runner._adapter_for_source = lambda source: runner._delivery_adapter_for(source)
    runner._is_user_authorized_for_source = lambda *_args, **_kwargs: True
    runner._adapter_flag = lambda *_args, **_kwargs: False
    runner.config = SimpleNamespace(
        multiplex_profiles=True,
        profile_routes=parse_profile_routes([{
            "platform": "discord", "guild_id": "GUILD", "chat_id": "PARENT", "profile": "developer",
        }]),
        _runtime_profile_homes=[("default", home), ("developer", satellite)],
    )
    route = "agent:developer:discord:thread:THREAD:THREAD"
    runner.session_store = SimpleNamespace(
        _generate_session_key=lambda _source: route,
        lookup_by_session_key=lambda _key: SimpleNamespace(session_id="SID"),
    )
    payload = {
        "text": "queued",
        "native_text_v1": {
            "route": route,
            "timestamp": "2026-11-01T02:52:21.870000+00:00",
            "provenance": {
                "connector": "fingerprint",
                "platform": "discord",
                "runtime_home": str(satellite),
                "transport_home": str(home),
                "transport_profile": None,
            },
            "source": {
                "platform": "discord",
                "chat_id": "THREAD",
                "chat_type": "thread",
                "thread_id": "THREAD",
                "parent_chat_id": "PARENT",
                "scope_id": "GUILD",
                "guild_id": "GUILD",
                "user_id": "USER",
                "profile": "developer",
                "is_bot": False,
                "message_id": "MSG",
            },
            "event": {"message_id": "MSG"},
        },
    }

    async def recover():
        return await check_native_route(runner, payload, "SID", _satellite_source(), None)

    try:
        source, resolved = asyncio.run(recover())
    except RuntimeStoreError as exc:
        raise AssertionError(f"paused: {exc.reason}") from exc
    assert resolved == route
    assert runner._adapter_for_source(source) is primary

from safe_assertions import require

import pytest

from eapolkit.settings import Settings


@pytest.fixture(autouse=True)
def clean_host_settings(monkeypatch):
    monkeypatch.delenv("EAPOLKIT_ALLOWED_HOSTS", raising=False)
    monkeypatch.delenv("EAPOLKIT_BIND_ADDRESS", raising=False)


def test_default_hosts_remain_loopback():
    require(Settings().allowed_hosts == ("localhost", "127.0.0.1", "::1"))


@pytest.mark.parametrize("bind", ["192.0.2.10", "127.0.0.2", "2001:db8::1"])
def test_one_concrete_bind_ip_adds_its_http_host(monkeypatch, bind):
    monkeypatch.setenv("EAPOLKIT_BIND_ADDRESS", bind)
    require(Settings().allowed_hosts == ("localhost", "127.0.0.1", "::1", bind))


@pytest.mark.parametrize("bind", ["127.0.0.1", "::1", "0.0.0.0", "::", "*", "", "host.invalid"])
def test_loopback_wildcard_or_non_ip_bind_does_not_expand_hosts(monkeypatch, bind):
    monkeypatch.setenv("EAPOLKIT_BIND_ADDRESS", bind)
    require(Settings().allowed_hosts == ("localhost", "127.0.0.1", "::1"))


def test_explicit_host_override_is_authoritative(monkeypatch):
    monkeypatch.setenv("EAPOLKIT_BIND_ADDRESS", "192.0.2.10")
    monkeypatch.setenv("EAPOLKIT_ALLOWED_HOSTS", "KIT.EXAMPLE.TEST, 127.0.0.1, ,")
    require(Settings().allowed_hosts == ("kit.example.test", "127.0.0.1"))


def test_empty_host_override_uses_automatic_defaults(monkeypatch):
    monkeypatch.setenv("EAPOLKIT_BIND_ADDRESS", "192.0.2.10")
    monkeypatch.setenv("EAPOLKIT_ALLOWED_HOSTS", "")
    require(Settings().allowed_hosts == ("localhost", "127.0.0.1", "::1", "192.0.2.10"))


def test_nonempty_blank_host_override_does_not_add_defaults(monkeypatch):
    monkeypatch.setenv("EAPOLKIT_BIND_ADDRESS", "192.0.2.10")
    monkeypatch.setenv("EAPOLKIT_ALLOWED_HOSTS", " , ")
    require(Settings().allowed_hosts == ())

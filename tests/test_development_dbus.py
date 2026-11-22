"""No host bus, keyring or credential access: exercise AUTH bytes and scoped use."""
import sys

import pytest

from rlredteam.api.development_dbus import host_uid_authentication
from rlredteam.api import local_config


@pytest.fixture
def development(monkeypatch):
    monkeypatch.setenv("SECURITY_RL_USE_LOCAL_CONFIG", "1")
    monkeypatch.setenv("SECURITY_RL_DBUS_AUTH_UID", "1234")
    monkeypatch.delattr(sys, "frozen", raising=False)


def test_claims_host_uid_and_restores_authenticator(development):
    import jeepney.auth
    original = jeepney.auth.make_auth_external
    with host_uid_authentication():
        assert jeepney.auth.make_auth_external() == b"AUTH EXTERNAL 31323334\r\n"
    assert jeepney.auth.make_auth_external is original


def test_restores_authenticator_after_failure(development):
    import jeepney.auth
    original = jeepney.auth.make_auth_external
    with pytest.raises(RuntimeError), host_uid_authentication():
        raise RuntimeError("synthetic failure")
    assert jeepney.auth.make_auth_external is original


@pytest.mark.parametrize("frozen,local_config_enabled", [(True, True), (False, False)])
def test_adapter_is_disabled_outside_development(development, monkeypatch, frozen, local_config_enabled):
    import jeepney.auth
    monkeypatch.setattr(sys, "frozen", frozen, raising=False)
    monkeypatch.setenv("SECURITY_RL_USE_LOCAL_CONFIG", "1" if local_config_enabled else "0")
    original = jeepney.auth.make_auth_external
    with host_uid_authentication():
        assert jeepney.auth.make_auth_external is original


@pytest.mark.parametrize("uid", ["", "-1", "user", "1234\r\nBEGIN", "4294967295", "１２３４"])
def test_rejects_invalid_uid(development, monkeypatch, uid):
    monkeypatch.setenv("SECURITY_RL_DBUS_AUTH_UID", uid)
    with pytest.raises(ValueError), host_uid_authentication():
        pass


def test_existing_secret_operations_use_adapter_without_plaintext_fallback(development, monkeypatch):
    import jeepney.auth
    class Vault:
        def set_password(self, service, account, value):
            assert jeepney.auth.make_auth_external() == b"AUTH EXTERNAL 31323334\r\n"
        def get_password(self, service, account):
            assert jeepney.auth.make_auth_external() == b"AUTH EXTERNAL 31323334\r\n"
            return "synthetic-secret"
    monkeypatch.setattr(local_config, "vault", Vault)
    local_config.secret("synthetic", "synthetic-secret", write=True)
    assert local_config.secret("synthetic") == "synthetic-secret"

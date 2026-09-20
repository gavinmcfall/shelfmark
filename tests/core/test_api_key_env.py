"""Tests for the API_KEY environment-variable authentication."""

from __future__ import annotations

import importlib
import logging
import os
import sqlite3
import tempfile
from unittest.mock import patch

import pytest

from shelfmark.core import api_key


@pytest.fixture
def user_db():
    from shelfmark.core.user_db import UserDB

    with tempfile.TemporaryDirectory() as tmpdir:
        db = UserDB(os.path.join(tmpdir, "users.db"))
        db.initialize()
        yield db


class TestExtractCandidates:
    def test_bearer_only(self):
        assert api_key.extract_api_key_candidates("Bearer a", None) == ["a"]

    def test_bearer_case_insensitive_and_trimmed(self):
        assert api_key.extract_api_key_candidates("bearer  a ", None) == ["a"]

    def test_x_api_key_only(self):
        assert api_key.extract_api_key_candidates(None, "b") == ["b"]

    def test_both_present(self):
        assert api_key.extract_api_key_candidates("Bearer a", "b") == ["a", "b"]

    def test_non_bearer_scheme_plus_x_api_key(self):
        assert api_key.extract_api_key_candidates("Basic dXNlcjpwYXNz", "b") == ["b"]

    def test_empty(self):
        assert api_key.extract_api_key_candidates("Bearer ", "") == []
        assert api_key.extract_api_key_candidates(None, None) == []


class TestMatches:
    def test_unset_never_matches(self, monkeypatch):
        monkeypatch.setattr(api_key, "API_KEY", "")
        assert api_key.matches_api_key("anything") is False
        assert api_key.matches_api_key("") is False

    def test_match(self, monkeypatch):
        monkeypatch.setattr(api_key, "API_KEY", "s3cret")
        assert api_key.matches_api_key("s3cret") is True

    def test_mismatch_and_prefix(self, monkeypatch):
        monkeypatch.setattr(api_key, "API_KEY", "s3cret")
        assert api_key.matches_api_key("s3cre") is False
        assert api_key.matches_api_key("s3cret ") is False
        assert api_key.matches_api_key("") is False


class TestFirstAdmin:
    def test_none_when_no_admin(self, user_db):
        user_db.create_user(username="alice")
        assert user_db.get_first_admin() is None

    def test_first_admin_by_id(self, user_db):
        user_db.create_user(username="alice")
        root = user_db.create_user(username="root", role="admin")
        user_db.create_user(username="root2", role="admin")
        assert user_db.get_first_admin()["id"] == root["id"]


@pytest.fixture(scope="module")
def main_module():
    """Import `shelfmark.main` with background startup disabled."""
    with patch("shelfmark.download.orchestrator.start"):
        import shelfmark.main as main

        importlib.reload(main)
        return main


@pytest.fixture
def wired(main_module, user_db, monkeypatch):
    monkeypatch.setattr(main_module, "user_db", user_db)
    monkeypatch.setattr(api_key, "API_KEY", "s3cret")
    with patch.object(main_module, "get_auth_mode", return_value="builtin"):
        yield main_module


@pytest.fixture
def real_user_db(main_module):
    """The UserDB main_module's self-service routes closed over at registration time.

    Unlike the isolated ``user_db``/``wired`` fixtures (a fresh temp DB
    monkeypatched onto ``main_module.user_db``), routes registered by
    ``register_self_user_routes`` keep their own reference to the UserDB
    passed in at import time, so tests that need those routes to see admin
    changes must write through this same instance. Any user created during
    the test is deleted again on teardown so state doesn't leak between
    tests sharing this module-scoped app.
    """
    db = main_module.user_db
    existing_ids = {user["id"] for user in db.list_users()}
    yield db
    for user in db.list_users():
        if user["id"] not in existing_ids:
            db.delete_user(user["id"])


def _bearer(value):
    return {"Authorization": f"Bearer {value}"}


def _x_api_key(value):
    return {"X-Api-Key": value}


def _cookie_client(app, user, *, is_admin=False, permanent=False):
    client = app.test_client()
    with client.session_transaction() as sess:
        sess["user_id"] = user["username"]
        sess["is_admin"] = is_admin
        sess["db_user_id"] = user["id"]
        sess.permanent = permanent
    return client


class TestKeyedRequests:
    def test_match_reaches_login_required_route(self, wired, user_db):
        user_db.create_user(username="root", role="admin")
        assert (
            wired.app.test_client()
            .get("/api/downloads/active", headers=_bearer("s3cret"))
            .status_code
            == 200
        )

    def test_match_is_admin(self, wired, user_db):
        user_db.create_user(username="root", role="admin")
        assert (
            wired.app.test_client().get("/api/settings", headers=_bearer("s3cret")).status_code
            == 200
        )

    def test_match_without_any_admin_user_is_still_admin(self, wired):
        assert (
            wired.app.test_client().get("/api/settings", headers=_bearer("s3cret")).status_code
            == 200
        )

    def test_match_no_user_db(self, main_module, monkeypatch):
        monkeypatch.setattr(main_module, "user_db", None)
        monkeypatch.setattr(api_key, "API_KEY", "s3cret")
        with patch.object(main_module, "get_auth_mode", return_value="builtin"):
            assert (
                main_module.app.test_client()
                .get("/api/downloads/active", headers=_bearer("s3cret"))
                .status_code
                == 200
            )

    def test_x_api_key(self, wired, user_db):
        user_db.create_user(username="root", role="admin")
        assert (
            wired.app.test_client()
            .get("/api/downloads/active", headers={"X-Api-Key": "s3cret"})
            .status_code
            == 200
        )

    def test_wrong_bearer_plus_correct_x_api_key_authenticates(self, wired, user_db):
        """A proxy's own Authorization header must not shadow a correct X-Api-Key."""
        user_db.create_user(username="root", role="admin")
        headers = {**_bearer("wrong"), **_x_api_key("s3cret")}
        assert wired.app.test_client().get("/api/settings", headers=headers).status_code == 200

    def test_correct_bearer_plus_wrong_x_api_key_authenticates(self, wired, user_db):
        user_db.create_user(username="root", role="admin")
        headers = {**_bearer("s3cret"), **_x_api_key("wrong")}
        assert wired.app.test_client().get("/api/settings", headers=headers).status_code == 200

    def test_no_set_cookie_even_when_handler_dirties_session(self, wired, user_db, monkeypatch):
        user_db.create_user(username="root", role="admin")
        original = wired.app.view_functions["api_active_downloads"]

        def dirty(*args, **kwargs):
            from flask import session

            session["dirty"] = True
            return original(*args, **kwargs)

        monkeypatch.setitem(wired.app.view_functions, "api_active_downloads", dirty)
        response = wired.app.test_client().get("/api/downloads/active", headers=_bearer("s3cret"))
        assert response.status_code == 200
        assert "Set-Cookie" not in response.headers

    def test_incoming_non_admin_cookie_is_ignored(self, wired, user_db):
        user_db.create_user(username="root", role="admin")
        alice = user_db.create_user(username="alice")
        client = _cookie_client(wired.app, alice)
        assert client.get("/api/settings", headers=_bearer("s3cret")).status_code == 200

    def test_matched_key_leaves_browser_cookie_usable(self, wired, user_db):
        user_db.create_user(username="root", role="admin")
        alice = user_db.create_user(username="alice")
        client = _cookie_client(wired.app, alice)
        assert client.get("/api/settings", headers=_bearer("s3cret")).status_code == 200

        assert client.get("/api/downloads/active").status_code == 200
        assert client.get("/api/settings").status_code == 403

    def test_security_headers_present(self, wired, user_db):
        user_db.create_user(username="root", role="admin")
        response = wired.app.test_client().get("/api/downloads/active", headers=_bearer("s3cret"))
        assert response.headers.get("X-Content-Type-Options") == "nosniff"

    def test_store_error_is_500_not_anonymous(self, wired, user_db, monkeypatch):
        monkeypatch.setattr(
            user_db,
            "get_first_admin",
            lambda: (_ for _ in ()).throw(sqlite3.OperationalError("boom")),
        )
        response = wired.app.test_client().get("/api/downloads/active", headers=_bearer("s3cret"))
        assert response.status_code == 500
        assert response.get_json() == {"error": "Authentication error"}


class TestMismatchFallsThrough:
    def test_mismatch_no_cookie_is_plain_unauthorized(self, wired):
        response = wired.app.test_client().get("/api/downloads/active", headers=_bearer("wrong"))
        assert response.status_code == 401
        assert response.get_json() == {"error": "Unauthorized"}

    def test_mismatch_is_indistinguishable_from_no_credential(self, wired):
        client = wired.app.test_client()
        no_credential = client.get("/api/downloads/active")
        with_wrong_bearer = client.get("/api/downloads/active", headers=_bearer("wrong"))

        assert no_credential.status_code == with_wrong_bearer.status_code
        assert no_credential.get_json() == with_wrong_bearer.get_json()

        ignored_headers = {"date", "content-length", "server"}

        def header_names(response):
            return {name.lower() for name in response.headers.keys()} - ignored_headers

        assert header_names(no_credential) == header_names(with_wrong_bearer)
        assert "WWW-Authenticate" not in no_credential.headers
        assert "WWW-Authenticate" not in with_wrong_bearer.headers

    def test_mismatch_writes_no_log(self, wired, caplog):
        with caplog.at_level(logging.INFO, logger="shelfmark"):
            wired.app.test_client().get("/api/downloads/active", headers=_bearer("wrong"))

        for record in caplog.records:
            message = record.getMessage()
            assert "API key" not in message
            assert "wrong" not in message

    def test_mismatch_with_cookie_uses_cookie(self, wired, user_db):
        alice = user_db.create_user(username="alice")
        client = _cookie_client(wired.app, alice)
        assert client.get("/api/downloads/active", headers=_bearer("wrong")).status_code == 200
        assert client.get("/api/settings", headers=_bearer("wrong")).status_code == 403

    def test_mismatch_leaves_browser_session_untouched(self, wired, user_db):
        alice = user_db.create_user(username="alice")
        client = _cookie_client(wired.app, alice, permanent=True)
        response = client.get("/api/downloads/active", headers=_bearer("wrong"))
        assert response.status_code == 200
        assert client.get("/api/downloads/active").status_code == 200

    def test_unset_key_is_noop(self, main_module, user_db, monkeypatch):
        monkeypatch.setattr(main_module, "user_db", user_db)
        monkeypatch.setattr(api_key, "API_KEY", "")
        with patch.object(main_module, "get_auth_mode", return_value="builtin"):
            response = main_module.app.test_client().get(
                "/api/downloads/active", headers=_bearer("s3cret")
            )
            assert response.status_code == 401
            assert response.get_json() == {"error": "Unauthorized"}

            alice = user_db.create_user(username="alice")
            client = _cookie_client(main_module.app, alice, permanent=True)
            cookie_response = client.get("/api/downloads/active", headers=_bearer("s3cret"))
        assert cookie_response.status_code == 200
        assert "Set-Cookie" in cookie_response.headers


class TestScopeAndModes:
    def test_health_and_auth_paths_and_root_ignore_key(self, wired):
        client = wired.app.test_client()
        assert client.get("/api/health", headers=_bearer("s3cret")).status_code == 200
        assert (
            client.get("/api/auth/check", headers=_bearer("s3cret")).get_json()["authenticated"]
            is False
        )
        assert client.get("/", headers=_bearer("s3cret")).status_code != 401

    def test_none_mode_noop(self, main_module, user_db, monkeypatch):
        monkeypatch.setattr(main_module, "user_db", user_db)
        monkeypatch.setattr(api_key, "API_KEY", "s3cret")
        with patch.object(main_module, "get_auth_mode", return_value="none"):
            assert (
                main_module.app.test_client()
                .get("/api/downloads/active", headers=_bearer("s3cret"))
                .status_code
                == 200
            )

    def test_proxy_mode_keyed_request_needs_no_proxy_header(
        self, main_module, user_db, monkeypatch
    ):
        monkeypatch.setattr(main_module, "user_db", user_db)
        monkeypatch.setattr(api_key, "API_KEY", "s3cret")
        user_db.create_user(username="root", role="admin", auth_source="proxy")
        with patch.object(main_module, "get_auth_mode", return_value="proxy"):
            assert (
                main_module.app.test_client()
                .get("/api/downloads/active", headers=_bearer("s3cret"))
                .status_code
                == 200
            )


class TestIdentityAndRouting:
    def test_deleted_first_admin_changes_identity(self, main_module, real_user_db, monkeypatch):
        monkeypatch.setattr(api_key, "API_KEY", "s3cret")
        root = real_user_db.create_user(username="root", role="admin")
        second = real_user_db.create_user(username="second", role="admin")

        with patch.object(main_module, "get_auth_mode", return_value="builtin"):
            client = main_module.app.test_client()

            response = client.get("/api/users/me/edit-context", headers=_bearer("s3cret"))
            assert response.status_code == 200
            assert response.get_json()["user"]["username"] == "root"

            real_user_db.delete_user(root["id"])

            response = client.get("/api/users/me/edit-context", headers=_bearer("s3cret"))
            assert response.status_code == 200
            assert response.get_json()["user"]["username"] == "second"

            real_user_db.delete_user(second["id"])

            # No admin row left at all; the key still authenticates a bare
            # admin identity for routes that don't need a local user row.
            response = client.get("/api/settings", headers=_bearer("s3cret"))
            assert response.status_code == 200

    def test_demoted_first_admin_changes_identity(self, main_module, real_user_db, monkeypatch):
        monkeypatch.setattr(api_key, "API_KEY", "s3cret")
        admin = real_user_db.create_user(username="root", role="admin")
        real_user_db.update_user(admin["id"], role="user")

        with patch.object(main_module, "get_auth_mode", return_value="builtin"):
            client = main_module.app.test_client()

            # Bare admin identity: no matching admin row, but still is_admin.
            response = client.get("/api/settings", headers=_bearer("s3cret"))
            assert response.status_code == 200

            # No db_user_id in session, so the self-user guard rejects it.
            response = client.get("/api/users/me/edit-context", headers=_bearer("s3cret"))
            assert response.status_code == 403

    def test_path_probes(self, wired, user_db):
        user_db.create_user(username="root", role="admin")
        client = wired.app.test_client()

        # Flask routing is case-sensitive: /API/... doesn't match the /api/
        # prefix the middleware checks, so it falls through to the SPA
        # catch-all route instead of the JSON handler with elevated state.
        response = client.get("/API/downloads/active", headers=_bearer("s3cret"))
        assert response.status_code != 200 or response.content_type != "application/json"

        # A trailing slash must not silently reach the handler either.
        response = client.get("/api/downloads/active/", headers=_bearer("s3cret"))
        assert response.status_code != 200 or not response.data

        # A dot-segment path trick must not resolve to a live route.
        response = client.get("/api/auth/../downloads/active", headers=_bearer("s3cret"))
        assert response.status_code == 404

    def test_keyed_post_reaches_mutating_route(self, wired, user_db, tmp_path, monkeypatch):
        """A keyed write through an admin-only settings route succeeds end to end."""
        import shelfmark.config.env as env_module

        # Isolate the settings write from the shared session CONFIG_DIR so this
        # test doesn't depend on (or pollute) other tests' persisted AUTH_METHOD.
        monkeypatch.setattr(env_module, "CONFIG_DIR", str(tmp_path))
        user_db.create_user(username="root", role="admin")

        response = wired.app.test_client().put(
            "/api/settings/security",
            json={"AUTH_METHOD": "none", "PROXY_AUTH_LOGOUT_URL": ""},
            headers=_bearer("s3cret"),
        )
        assert response.status_code == 200

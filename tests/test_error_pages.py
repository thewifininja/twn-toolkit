import pytest

from twn_toolkit import create_app
from twn_toolkit.auth import AuthStore

PASSWORD = "correct horse battery staple"
NAVIGATION = {"Sec-Fetch-Mode": "navigate", "Sec-Fetch-Dest": "document", "Accept": "text/html"}


@pytest.fixture()
def clients(tmp_path):
    app = create_app(str(tmp_path))
    store = AuthStore(str(tmp_path))
    store.create_initial_admin("admin", PASSWORD)
    store.create_user("operator", PASSWORD)

    def signed_in(username):
        client = app.test_client()
        assert client.post("/login", data={"username": username, "password": PASSWORD}).status_code == 302
        return client

    return app, signed_in("admin"), signed_in("operator")


def test_navigating_to_a_denied_tool_keeps_the_operator_inside_the_application(clients):
    _, _, operator = clients
    response = operator.get("/tools/ping", headers=NAVIGATION)
    assert response.status_code == 403
    assert b"This account cannot open that page" in response.data
    assert b"Return to the dashboard" in response.data
    assert b'id="app-sidebar"' in response.data
    assert response.headers["Cache-Control"] == "no-store"
    # The denied tool's own form must not be rendered behind the message.
    assert b'name="hosts"' not in response.data


def test_script_requests_keep_the_plain_denial(clients):
    _, _, operator = clients
    for headers in ({}, {"Accept": "*/*"}, {"Sec-Fetch-Mode": "cors", "Accept": "text/html"},
                    {**NAVIGATION, "X-Requested-With": "XMLHttpRequest"},
                    {**NAVIGATION, "Sec-Fetch-Dest": "iframe"}):
        response = operator.get("/tools/ping", headers=headers)
        assert response.status_code == 403
        assert response.data == b"This user does not have access to that tool."


@pytest.mark.parametrize("path, status, text", [
    ("/no-such-page", 404, b"That page is not available"),
    ("/settings/users", 405, b"That address cannot be opened directly"),
])
def test_missing_and_post_only_addresses_render_a_navigable_page(clients, path, status, text):
    _, admin, _ = clients
    response = admin.get(path, headers=NAVIGATION)
    assert response.status_code == status
    assert text in response.data
    assert b"Return to the dashboard" in response.data
    plain = admin.get(path)
    assert plain.status_code == status
    if status == 405:
        assert response.headers["Allow"] == plain.headers["Allow"]
    assert b"Return to the dashboard" not in plain.data


def test_explicit_html_accept_without_fetch_metadata_renders_the_page(clients):
    _, admin, _ = clients
    response = admin.get("/no-such-page", headers={"Accept": "text/html,application/xhtml+xml"})
    assert response.status_code == 404
    assert b"That page is not available" in response.data


def test_mutations_never_receive_the_error_page(clients):
    _, admin, _ = clients
    response = admin.post("/no-such-page", headers=NAVIGATION)
    assert response.status_code == 404
    assert b"Return to the dashboard" not in response.data


def test_unexpected_failure_page_does_not_disclose_the_exception(clients):
    app, admin, _ = clients

    def synthetic_failure():
        raise RuntimeError("synthetic secret detail")

    app.view_functions["help_page"] = synthetic_failure
    response = admin.get("/help", headers=NAVIGATION)
    assert response.status_code == 500
    assert b"The toolkit could not complete that request" in response.data
    assert b"synthetic secret detail" not in response.data


def test_redirects_and_unauthenticated_requests_are_unchanged(clients):
    app, _, _ = clients
    anonymous = app.test_client()
    response = anonymous.get("/no-such-page", headers=NAVIGATION)
    assert response.status_code == 302
    assert response.headers["Location"].startswith("/login")

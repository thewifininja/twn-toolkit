import pytest

from twn_toolkit import create_app
from twn_toolkit.local_redirects import local_redirect_target


@pytest.mark.parametrize("candidate", [
    "/", "/tools/ping", "/tools/ping?host=192.0.2.1&count=3#results",
    "/investigations/abc/report?report_page=2", "/agents/agent_ab/ui/tools/ping",
])
def test_same_origin_paths_are_preserved(candidate):
    assert local_redirect_target(candidate, "/fallback") == candidate


@pytest.mark.parametrize("candidate", [
    "", "tools/ping", "//example.com/phishing", "https://example.com/",
    "/\\example.com", "/\\/example.com", "\\/example.com",
    "/\t/example.com", "/\n/example.com", "/\r/example.com", "/\x00/example.com",
    "/tools\x7f", None, 7,
])
def test_targets_a_browser_could_resolve_elsewhere_use_the_default(candidate):
    assert local_redirect_target(candidate, "/fallback") == "/fallback"


@pytest.mark.parametrize("candidate", ["/\t/example.com", "/\\example.com", "/\n/example.com"])
def test_login_never_redirects_to_another_origin(tmp_path, candidate):
    app = create_app(str(tmp_path))
    client = app.test_client()
    password = "correct horse battery staple"
    client.post("/setup", data={
        "username": "admin", "password": password, "confirm_password": password,
    })
    client.post("/logout")
    # The sign-in page must not carry the unsafe target into its hidden field.
    page = client.get("/login", query_string={"next": candidate})
    assert b'name="next" value="/"' in page.data
    response = client.post("/login", data={
        "username": "admin", "password": password, "next": candidate,
    })
    assert response.status_code == 302
    assert response.headers["Location"] == "/"

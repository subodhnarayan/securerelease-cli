import httpx
import pytest

from securerelease.auth import AuthError, bearer_header_from_env, cookies_from_storage_state, header_from_env, redact
from securerelease.scanners.http_baseline import TargetRejected
from securerelease.scanners.safe_http import BudgetExceeded, SafeClient, ScopeViolation


def make_client(handler, **kwargs):
    return SafeClient("http://127.0.0.1:9000", allow_private=True, transport=httpx.MockTransport(handler), **kwargs)


def ok(request):
    return httpx.Response(200, text="hello", headers={"Set-Cookie": "a=b"})


def test_private_target_rejected_without_opt_in():
    with pytest.raises(TargetRejected):
        SafeClient("http://127.0.0.1:9000", transport=httpx.MockTransport(ok))


def test_cross_origin_requests_are_refused():
    with make_client(ok) as client, pytest.raises(ScopeViolation):
        client.get("http://127.0.0.1:9001/")


def test_mutating_methods_need_opt_in():
    with make_client(ok) as client:
        with pytest.raises(ScopeViolation):
            client.request("POST", "http://127.0.0.1:9000/x")
    with make_client(ok, allow_mutating=True) as client:
        assert client.request("POST", "http://127.0.0.1:9000/x").status == 200


def test_request_budget_is_enforced():
    with make_client(ok, max_requests=2) as client:
        client.get("http://127.0.0.1:9000/1")
        client.get("http://127.0.0.1:9000/2")
        with pytest.raises(BudgetExceeded):
            client.get("http://127.0.0.1:9000/3")


def test_body_is_capped_and_redacted():
    handler = lambda request: httpx.Response(200, text="token=supersecret " + "x" * 5000)  # noqa: E731
    with make_client(handler, secrets=["supersecret"]) as client:
        reply = client.get("http://127.0.0.1:9000/", max_body=1024)
    assert reply.truncated and len(reply.body) <= 1024 and "supersecret" not in reply.body and "[REDACTED]" in reply.body


def test_auth_headers_can_be_omitted_and_cookies_do_not_persist():
    seen = []

    def handler(request):
        seen.append((request.headers.get("authorization"), request.headers.get("cookie")))
        return httpx.Response(200, headers={"Set-Cookie": "sid=1"})

    with make_client(handler, headers={"Authorization": "Bearer abc"}) as client:
        client.get("http://127.0.0.1:9000/")
        client.get("http://127.0.0.1:9000/", auth=False)
    assert seen == [("Bearer abc", None), (None, None)]


def test_env_credentials_validate_and_redact():
    headers, secrets = bearer_header_from_env("T", {"T": "abcd1234"})
    assert headers == {"Authorization": "Bearer abcd1234"} and "abcd1234" in secrets
    assert bearer_header_from_env("T", {"T": "Basic Zm9v"})[0] == {"Authorization": "Basic Zm9v"}
    assert header_from_env("H", {"H": "X-Api-Key: k3y-value"})[0] == {"X-Api-Key": "k3y-value"}
    with pytest.raises(AuthError):
        bearer_header_from_env("MISSING", {})
    with pytest.raises(AuthError):
        header_from_env("H", {"H": "no-colon"})
    assert redact("a abcd1234 b", ["abcd1234"]) == "a [REDACTED] b"


def test_storage_state_cookies_filtered_by_host(tmp_path):
    state = tmp_path / "state.json"
    state.write_text('{"cookies": [{"name": "s", "value": "v1234", "domain": ".example.test"}, '
                     '{"name": "o", "value": "zzzz", "domain": "other.test"}]}')
    cookies, secrets = cookies_from_storage_state(state, "app.example.test")
    assert cookies == {"s": "v1234"} and secrets == ["v1234"]
    with pytest.raises(AuthError):
        cookies_from_storage_state(tmp_path / "missing.json", "x")


def test_tls_verify_honors_custom_ca_bundle(tmp_path, monkeypatch):
    from securerelease.scanners.http_baseline import tls_verify

    for name in ("SECURERELEASE_CA_BUNDLE", "SSL_CERT_FILE", "REQUESTS_CA_BUNDLE"):
        monkeypatch.delenv(name, raising=False)
    assert tls_verify() is True
    bundle = tmp_path / "ca.pem"
    bundle.write_text("x")
    monkeypatch.setenv("SECURERELEASE_CA_BUNDLE", str(bundle))
    assert tls_verify() == str(bundle)
    monkeypatch.setenv("SECURERELEASE_CA_BUNDLE", str(tmp_path / "missing.pem"))
    assert tls_verify() is True

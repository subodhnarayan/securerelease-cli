import importlib.util
from pathlib import Path
from threading import Thread

import pytest

FIXTURES = Path(__file__).parent / "fixtures"


def _load(name: str):
    spec = importlib.util.spec_from_file_location(f"fixture_{name}", FIXTURES / name / "server.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _serve(name: str):
    server = _load(name).make_server(0)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, f"http://127.0.0.1:{server.server_address[1]}"


@pytest.fixture(scope="session")
def mini_api_url():
    server, url = _serve("mini_api")
    yield url
    server.shutdown()
    server.server_close()


@pytest.fixture(scope="session")
def mini_ui_url():
    server, url = _serve("mini_ui")
    yield url
    server.shutdown()
    server.server_close()


@pytest.fixture
def api_env():
    return {"TOKEN_ALICE": "token-alice", "TOKEN_BOB": "token-bob"}


def by_id(findings):
    return {f.check_id: f for f in findings}

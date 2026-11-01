import os
import stat
from pathlib import Path

import pytest

from securerelease.cli import main
from securerelease.envfile import EnvFileError, apply_env, as_bool, parse_env
from securerelease.wizard import run_init

ROOT = Path(__file__).parent.parent


@pytest.fixture(autouse=True)
def clean_environment():
    saved = dict(os.environ)
    for key in [k for k in os.environ if k.startswith("SECURERELEASE_")]:
        del os.environ[key]
    yield
    os.environ.clear()
    os.environ.update(saved)


def test_parse_env_handles_comments_quotes_and_export():
    text = '# c\n\nexport A=1\nB="two words # kept"\nC=\'x\'\nD=plain  # trailing\nE=\n'
    assert parse_env(text) == {"A": "1", "B": "two words # kept", "C": "x", "D": "plain", "E": ""}


@pytest.mark.parametrize("bad", ["no equals", "1BAD=x", 'A="open'])
def test_parse_env_rejects_malformed_lines(bad):
    with pytest.raises(EnvFileError):
        parse_env(bad)


def test_apply_env_never_overrides_existing_values():
    target = {"A": "real"}
    assert apply_env({"A": "file", "B": "file"}, target) == ["B"] and target == {"A": "real", "B": "file"}


def test_as_bool():
    assert as_bool("TRUE") and as_bool("yes") and not as_bool("") and not as_bool("0")
    with pytest.raises(EnvFileError):
        as_bool("maybe")


def test_env_example_is_valid_and_safe_by_default():
    values = parse_env((ROOT / ".env.example").read_text())
    assert values["SECURERELEASE_AUTHORIZED"] == "false" and values["SECURERELEASE_ALLOW_MUTATING"] == "false"
    assert values["SECURERELEASE_ALLOW_PRIVATE_TARGETS"] == "false"
    assert not values["SECURERELEASE_API_TOKEN"] and not values["SECURERELEASE_UI_PASSWORD"]
    assert all(key.startswith("SECURERELEASE_") for key in values)
    assert ".env" in (ROOT / ".gitignore").read_text().splitlines()


def write_env(tmp_path, ui, api, extra=""):
    (tmp_path / ".env").write_text(
        f"SECURERELEASE_UI_URL={ui}\nSECURERELEASE_API_URL={api}\nSECURERELEASE_API_TOKEN=token-alice\n"
        f"SECURERELEASE_API_TOKEN_B=token-bob\nSECURERELEASE_ALLOW_PRIVATE_TARGETS=true\nSECURERELEASE_UI_ENGINE=crawler\n{extra}")


def test_run_uses_dotenv_and_writes_an_html_report(mini_ui_url, mini_api_url, tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    write_env(tmp_path, mini_ui_url, mini_api_url, "SECURERELEASE_AUTHORIZED=true\n")
    code = main(["run"])
    captured = capsys.readouterr()
    report = (tmp_path / "reports" / "securerelease-report.html").read_text()
    assert code == 1
    assert "Profile     : full" in captured.err and "Active tests: ON" in captured.err
    assert "user A set, user B set" in captured.err and "token-alice" not in captured.err + captured.out + report
    assert "UI scanner" in report and "API scanner" in report
    assert "Object-level authorization" in report and "FAIL" in report


def test_command_line_flags_override_the_file(mini_ui_url, mini_api_url, tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    write_env(tmp_path, mini_ui_url, mini_api_url)
    code = main(["run", "--profile", "ui", "--format", "json", "--output", "out.json", "--no-fail-on-findings"])
    assert code == 0 and (tmp_path / "out.json").exists() and not (tmp_path / "reports").exists()
    assert "Profile     : ui" in capsys.readouterr().err and '"profile": "ui"' in (tmp_path / "out.json").read_text()


def test_real_environment_overrides_the_file(mini_ui_url, mini_api_url, tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    write_env(tmp_path, mini_ui_url, mini_api_url, "SECURERELEASE_PROFILE=api\n")
    monkeypatch.setenv("SECURERELEASE_PROFILE", "ui")
    main(["run", "--no-fail-on-findings"])
    assert "Profile     : ui" in capsys.readouterr().err


def test_profile_is_inferred_from_configured_targets(mini_api_url, tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".env").write_text(f"SECURERELEASE_API_URL={mini_api_url}\nSECURERELEASE_ALLOW_PRIVATE_TARGETS=true\n")
    main(["run", "--no-fail-on-findings"])
    assert "Profile     : api" in capsys.readouterr().err


def test_run_without_targets_explains_what_to_do(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    with pytest.raises(SystemExit) as exc:
        main(["run"])
    assert exc.value.code == 2 and "securerelease init" in capsys.readouterr().err


def test_missing_explicit_env_file_and_bad_values_are_errors(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    with pytest.raises(SystemExit):
        main(["run", "--env-file", "nope.env"])
    assert "not found" in capsys.readouterr().err
    (tmp_path / ".env").write_text("SECURERELEASE_UI_URL=http://x.test\nSECURERELEASE_MAX_PAGES=lots\n")
    with pytest.raises(SystemExit):
        main(["run"])
    assert "Invalid value" in capsys.readouterr().err


def test_scan_accepts_env_file_but_only_uses_targets_its_profile_allows(mini_ui_url, mini_api_url, tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    write_env(tmp_path, mini_ui_url, mini_api_url)
    code = main(["ui-scan", "--env-file", ".env", "--no-fail-on-findings"])
    out = capsys.readouterr().out
    assert code == 0 and "profile=ui" in out and mini_api_url not in out
    code = main(["scan", "--profile", "api", "--env-file", ".env", "--no-fail-on-findings"])
    assert code == 0 and "profile=api" in capsys.readouterr().out


def test_dotenv_is_not_read_by_plain_scan_commands(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".env").write_text("SECURERELEASE_UI_URL=http://127.0.0.1:1\n")
    with pytest.raises(SystemExit):
        main(["ui-scan"])


def answers(values):
    items = iter(values)
    return lambda prompt: next(items)


def test_init_wizard_writes_a_private_env_file_that_run_understands(tmp_path):
    target = tmp_path / ".env"
    messages = []
    code = run_init(
        str(target),
        input_fn=answers(["not-a-url", "https://app.example.com", "https://api.example.com", "./openapi.json", "",
                          "y", "y", "y", "https://app.example.com/login", "tester", "n", "n"]),
        secret_fn=answers(["tok-A", "tok-B", "p@ss word"]),
        out=messages.append,
    )
    assert code == 0 and any("full URL" in m for m in messages)
    assert stat.S_IMODE(target.stat().st_mode) == 0o600
    values = parse_env(target.read_text())
    assert values["SECURERELEASE_UI_URL"] == "https://app.example.com" and values["SECURERELEASE_API_TOKEN_B"] == "tok-B"
    assert values["SECURERELEASE_UI_PASSWORD"] == "p@ss word" and values["SECURERELEASE_AUTHORIZED"] == "false"
    assert values["SECURERELEASE_ALLOW_PRIVATE_TARGETS"] == "false"


def test_init_wizard_refuses_to_overwrite_and_needs_a_target(tmp_path):
    target = tmp_path / ".env"
    target.write_text("keep=me\n")
    assert run_init(str(target), input_fn=answers(["n"]), secret_fn=answers([]), out=lambda m: None) == 1
    assert target.read_text() == "keep=me\n"
    assert run_init(str(tmp_path / "new.env"), input_fn=answers(["", "", ""]), secret_fn=answers([]), out=lambda m: None) == 1
    assert not (tmp_path / "new.env").exists()

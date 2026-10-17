"""T6 (#134889): classic-CLI ``/config`` on a Vertex route names the credential honestly.

The gateway-backed CLI resolves Vertex under ``deferred_token_mint``: its ``api_key`` is
``agent.vertex_adapter.vertex_access_token``, a callable that mints a Google OAuth token on first
use (the gateway mints its own for the turn). ``/config`` saw "a callable" and printed the Azure
label "Microsoft Entra ID". It must say Google OAuth and must never call the callable: masking a
token would mean a second JWT exchange from the CLI process, the double mint #106742 removed.
"""

from __future__ import annotations

from datetime import datetime

from agent.i18n import t
from cli import HermesCLI


def _config_text(capsys, api_key) -> str:
    cli = HermesCLI.__new__(HermesCLI)
    cli.api_key, cli.agent = api_key, None
    cli.model = "google/gemini-3-flash-preview"
    cli.base_url = "https://us-central1-aiplatform.googleapis.com/v1beta1/projects/p/locations/us-central1/endpoints/openapi"
    cli.max_turns, cli.enabled_toolsets, cli.verbose = 10, [], False
    cli.session_start = datetime(2031, 1, 1)
    cli.show_config()
    return capsys.readouterr().out


def test_config_labels_vertex_callable_as_google_oauth_without_minting(capsys, monkeypatch):
    import agent.vertex_adapter as va

    mints: list[int] = []
    monkeypatch.setattr(va, "get_vertex_credentials", lambda *_a, **_k: mints.append(1) or ("ya29.x", "p"))
    out = _config_text(capsys, va.vertex_access_token)

    api_line = next(line for line in out.splitlines() if t("cli.config.label_api_key") in line)
    assert t("cli.config.google_vertex_oauth") in api_line, out
    assert t("cli.config.microsoft_entra_id") not in out, out
    assert mints == [], "/config minted a Vertex token just to display it"


def test_config_keeps_entra_label_for_other_token_providers(capsys):
    def entra_bearer_provider() -> str:
        raise AssertionError("never invoked")

    out = _config_text(capsys, entra_bearer_provider)
    assert t("cli.config.microsoft_entra_id") in out, out

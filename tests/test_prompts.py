from __future__ import annotations

from pathlib import Path

from zion_eval.prompts import build_chooser_prompt, build_reverse_prompt


def test_runtime_contract_directory_is_authoritative(
    tmp_path: Path, monkeypatch
) -> None:
    prompt_dir = tmp_path / "contracts" / "prompts"
    prompt_dir.mkdir(parents=True)
    (prompt_dir / "reverser.md").write_text(
        "contract {count} {server_id} {backend}\n", encoding="utf-8"
    )
    monkeypatch.setenv("ZION_EVAL_CONTRACTS_DIR", str(tmp_path / "contracts"))

    assert build_reverse_prompt(7, "server", "angr") == "contract 7 server angr\n"


def test_chooser_prompt_uses_reviewed_contract_file(
    tmp_path: Path, monkeypatch
) -> None:
    prompt_dir = tmp_path / "prompts"
    prompt_dir.mkdir()
    (prompt_dir / "chooser.md").write_text(
        "choose {count} {server_id} {backend}\n", encoding="utf-8"
    )
    monkeypatch.setenv("ZION_EVAL_CONTRACTS_DIR", str(tmp_path))
    assert build_chooser_prompt(5, "server", "ida") == "choose 5 server ida\n"

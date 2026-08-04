from __future__ import annotations

from pathlib import Path

from zion_eval.prompts import build_reverse_prompt


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

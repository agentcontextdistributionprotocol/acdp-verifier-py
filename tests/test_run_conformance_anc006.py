"""anc-006 executor: the pure vector checker accepts the real fixture and fails loudly on drift."""

from __future__ import annotations

import copy
import hashlib
from typing import Any

import pytest
from test_seamdecision import DIGEST_A, DIGEST_B, INPUTS_A, INPUTS_B, PREIMAGE_A, PREIMAGE_B

import run_conformance
from run_conformance import CheckFailure


def _anchor(digest_hex: str) -> dict[str, str]:
    return {"scheme": "seam.decision", "content_hash": "sha256:" + digest_hex}


def _expected(outcome: str, anchor_verdict: str) -> dict[str, str]:
    return {
        "outcome": outcome,
        "anchor_verdict": anchor_verdict,
        "body_verification_verdict": "valid",
    }


def _vector(inputs: dict[str, Any], preimage: str, digest: str) -> dict[str, Any]:
    return {
        "inputs": inputs,
        "preimage_hex": preimage,
        "digest_hex": digest,
        "anchor": _anchor(digest),
    }


# The anc-006 fixture at spec 1ed9bec, reduced to the members the executor reads.
FIXTURE: dict[str, Any] = {
    "id": "anc-006",
    "scenarios": [
        {
            "name": "A — known vector, policy bound",
            "vector": _vector(INPUTS_A, PREIMAGE_A, DIGEST_A),
            "expected": _expected("success", "match"),
        },
        {
            "name": "B — known vector, no policy bound",
            "vector": _vector(INPUTS_B, PREIMAGE_B, DIGEST_B),
            "expected": _expected("success", "match"),
        },
        {
            "name": "C — anchor names a different digest",
            "input": {"record": "scenario A's inputs", "anchor": _anchor(DIGEST_B)},
            "expected": _expected("anchor_invalid", "mismatch"),
        },
        {
            "name": "D — unknown record-digest version",
            "input": {
                "record": "scenario A's inputs with schema_version = 3",
                "anchor": _anchor(DIGEST_A),
            },
            "expected": _expected("anchor_cannot_verify", "cannot_verify"),
        },
    ],
}


def _doctored() -> dict[str, Any]:
    return copy.deepcopy(FIXTURE)


def _flip_preimage_byte(f: dict[str, Any]) -> None:
    vector = f["scenarios"][0]["vector"]
    raw = bytearray(bytes.fromhex(vector["preimage_hex"]))
    raw[-1] ^= 0x01
    vector["preimage_hex"] = raw.hex()


def _flip_preimage_byte_and_digest(f: dict[str, Any]) -> None:
    # Self-consistent but wrong: only our own recomputation can catch it.
    _flip_preimage_byte(f)
    vector = f["scenarios"][0]["vector"]
    vector["digest_hex"] = hashlib.sha256(bytes.fromhex(vector["preimage_hex"])).hexdigest()
    vector["anchor"] = _anchor(vector["digest_hex"])


def _set(path: tuple[Any, ...], value: Any) -> Any:
    def mutate(f: dict[str, Any]) -> None:
        target: Any = f
        for key in path[:-1]:
            target = target[key]
        target[path[-1]] = value

    return mutate


def _remove_d(f: dict[str, Any]) -> None:
    f["scenarios"] = f["scenarios"][:3]


def _duplicate_c(f: dict[str, Any]) -> None:
    f["scenarios"].append(copy.deepcopy(f["scenarios"][2]))


def test_real_fixture_passes() -> None:
    anchors = run_conformance._check_anc006_vectors(FIXTURE)
    assert anchors == {
        "A": _anchor(DIGEST_A),
        "B": _anchor(DIGEST_B),
        "C": _anchor(DIGEST_B),
        "D": _anchor(DIGEST_A),
    }


def test_checker_does_not_mutate_fixture() -> None:
    fixture = _doctored()
    run_conformance._check_anc006_vectors(fixture)
    assert fixture == FIXTURE


@pytest.mark.parametrize(
    ("mutate", "message"),
    [
        (_flip_preimage_byte, "does not hash to digest_hex"),
        (_flip_preimage_byte_and_digest, "recomputed preimage differs"),
        (_set(("scenarios", 2, "expected", "anchor_verdict"), "match"), "anchor verdict"),
        (_set(("scenarios", 2, "expected", "outcome"), "success"), "outcome"),
        (_set(("scenarios", 3, "expected", "anchor_verdict"), "match"), "anchor verdict"),
        (_remove_d, "exactly one scenario D"),
        (_duplicate_c, "exactly one scenario C"),
        (_set(("scenarios", 3, "input", "record"), "scenario A's inputs"), "D: record"),
        (_set(("scenarios", 2, "input", "record"), "scenario B's inputs"), "C: record"),
        (
            _set(("scenarios", 1, "expected", "body_verification_verdict"), "invalid"),
            "contradicts",
        ),
        (_set(("scenarios", 2, "input", "anchor"), _anchor("00" * 32)), "scenario B's digest"),
        (_set(("scenarios", 3, "input", "anchor"), _anchor(DIGEST_B)), "scenario A's digest"),
        (_set(("scenarios", 0, "vector", "anchor"), _anchor(DIGEST_B)), "not the vector digest"),
        (
            _set(("scenarios", 0, "vector", "inputs", "tenant"), None),
            "vector inputs refused",
        ),
    ],
)
def test_doctored_fixture_fails(mutate: Any, message: str) -> None:
    fixture = _doctored()
    mutate(fixture)
    with pytest.raises(CheckFailure, match=message):
        run_conformance._check_anc006_vectors(fixture)

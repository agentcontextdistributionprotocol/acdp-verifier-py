"""Merkle tree tests: proof folding across edge tree sizes, brute-force cross-check."""

from __future__ import annotations

import base64
import hashlib
from typing import Any

import pytest

from acdp_verifier import jcs, signing, translog
from acdp_verifier.errors import InvalidLogProof, InvalidReceipt
from acdp_verifier.hashing import sha256_prefixed


def leaves(n: int) -> list[bytes]:
    return [hashlib.sha256(b"\x00" + bytes([i])).digest() for i in range(n)]


class TestMth:
    def test_empty_tree(self) -> None:
        assert (
            translog.merkle_tree_hash([]).hex()
            == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        )

    def test_single_leaf_is_its_hash(self) -> None:
        d = leaves(1)
        assert translog.merkle_tree_hash(d) == d[0]

    def test_two_leaves(self) -> None:
        d = leaves(2)
        assert translog.merkle_tree_hash(d) == translog.node_hash(d[0], d[1])


class TestInclusion:
    @pytest.mark.parametrize("n", list(range(1, 9)))
    def test_every_index_every_size(self, n: int) -> None:
        d = leaves(n)
        root = translog.merkle_tree_hash(d)
        for i in range(n):
            path = translog.compute_inclusion_path(i, d)
            translog.verify_inclusion(
                leaf_hash_value=d[i],
                leaf_index=i,
                tree_size=n,
                inclusion_path=path,
                root_hash=root,
            )

    def test_tampered_path_fails(self) -> None:
        d = leaves(5)
        root = translog.merkle_tree_hash(d)
        path = translog.compute_inclusion_path(0, d)
        bad = [path[0][::-1], *path[1:]]
        with pytest.raises(InvalidLogProof):
            translog.verify_inclusion(
                leaf_hash_value=d[0],
                leaf_index=0,
                tree_size=5,
                inclusion_path=bad,
                root_hash=root,
            )

    def test_path_too_long_and_too_short(self) -> None:
        d = leaves(5)
        root = translog.merkle_tree_hash(d)
        path = translog.compute_inclusion_path(0, d)
        with pytest.raises(InvalidLogProof):
            translog.verify_inclusion(
                leaf_hash_value=d[0],
                leaf_index=0,
                tree_size=5,
                inclusion_path=[*path, d[1]],
                root_hash=root,
            )
        with pytest.raises(InvalidLogProof):
            translog.verify_inclusion(
                leaf_hash_value=d[0],
                leaf_index=0,
                tree_size=5,
                inclusion_path=path[:-1],
                root_hash=root,
            )

    def test_index_out_of_range(self) -> None:
        d = leaves(3)
        with pytest.raises(InvalidLogProof):
            translog.verify_inclusion(
                leaf_hash_value=d[0],
                leaf_index=3,
                tree_size=3,
                inclusion_path=[],
                root_hash=translog.merkle_tree_hash(d),
            )

    def test_size_one_tree_empty_path(self) -> None:
        d = leaves(1)
        translog.verify_inclusion(
            leaf_hash_value=d[0],
            leaf_index=0,
            tree_size=1,
            inclusion_path=[],
            root_hash=d[0],
        )


class TestConsistency:
    @pytest.mark.parametrize("n", list(range(1, 9)))
    def test_every_prefix_every_size(self, n: int) -> None:
        d = leaves(n)
        second_root = translog.merkle_tree_hash(d)
        for m in range(1, n + 1):
            first_root = translog.merkle_tree_hash(d[:m])
            path = translog.compute_consistency_path(m, d)
            translog.verify_consistency(
                first=m,
                second=n,
                consistency_path=path,
                first_root=first_root,
                second_root=second_root,
            )

    def test_rewritten_history_fails(self) -> None:
        d = leaves(5)
        rewritten = list(d)
        rewritten[1] = hashlib.sha256(b"\x00evil").digest()
        first_root = translog.merkle_tree_hash(d[:3])
        second_root = translog.merkle_tree_hash(rewritten)
        path = translog.compute_consistency_path(3, rewritten)
        with pytest.raises(InvalidLogProof):
            translog.verify_consistency(
                first=3,
                second=5,
                consistency_path=path,
                first_root=first_root,
                second_root=second_root,
            )

    def test_equal_sizes_empty_path(self) -> None:
        d = leaves(4)
        root = translog.merkle_tree_hash(d)
        translog.verify_consistency(
            first=4, second=4, consistency_path=[], first_root=root, second_root=root
        )
        with pytest.raises(InvalidLogProof):
            translog.verify_consistency(
                first=4,
                second=4,
                consistency_path=[],
                first_root=root,
                second_root=leaves(1)[0],
            )

    def test_first_zero_fails(self) -> None:
        d = leaves(4)
        with pytest.raises(InvalidLogProof):
            translog.verify_consistency(
                first=0,
                second=4,
                consistency_path=[d[0]],
                first_root=d[0],
                second_root=translog.merkle_tree_hash(d),
            )

    def test_power_of_two_first(self) -> None:
        # first == 4 (exact power of two) exercises the root-prepend branch.
        d = leaves(7)
        first_root = translog.merkle_tree_hash(d[:4])
        second_root = translog.merkle_tree_hash(d)
        path = translog.compute_consistency_path(4, d)
        translog.verify_consistency(
            first=4,
            second=7,
            consistency_path=path,
            first_root=first_root,
            second_root=second_root,
        )


class TestDomainSeparation:
    def test_leaf_prefix_required(self) -> None:
        leaf = {
            "leaf_version": "acdp-log-leaf/1",
            "ctx_id": "acdp://r.example/00000000-0000-4000-8000-000000000001",
            "lineage_id": "lin:sha256:" + "0" * 64,
            "origin_registry": "r.example",
            "created_at": "2026-07-01T00:00:00.000Z",
            "content_hash": "sha256:" + "0" * 64,
            "key_fingerprint": "sha256:" + "0" * 64,
            "receipt_hash": "sha256:" + "0" * 64,
        }
        from acdp_verifier import jcs

        with_prefix = translog.leaf_hash(leaf)
        without = hashlib.sha256(jcs.canonicalize_any(leaf)).digest()
        assert with_prefix != without

    def test_leaf_shape_closed(self) -> None:
        with pytest.raises(InvalidLogProof):
            translog.leaf_hash({"leaf_version": "acdp-log-leaf/1"})

    def test_hash_wire_form(self) -> None:
        digest = bytes(32)
        assert translog.parse_hash(translog.unparse_hash(digest)) == digest
        with pytest.raises(InvalidLogProof):
            translog.parse_hash("sha256:XYZ")


class TestLogInclusionVerdict:
    """RFC-ACDP-0012 §9.1 (0.5.0): inclusion needs a verified receipt."""

    SEED = bytes([0x11] * 32)

    def _leaf(self, i: int) -> dict[str, Any]:
        return {
            "leaf_version": translog.LEAF_VERSION,
            "ctx_id": f"acdp://registry.example.com/{i:08d}-1234-4321-8123-123456781234",
            "lineage_id": "lin:sha256:" + "c7" * 32,
            "origin_registry": "registry.example.com",
            "created_at": "2026-04-16T10:30:15.123Z",
            "content_hash": "sha256:" + f"{i:02x}" * 32,
            "key_fingerprint": "sha256:" + "13" * 32,
            "receipt_hash": "sha256:" + "9d" * 32,
        }

    def _setup(self) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
        leaf_objs = [self._leaf(i) for i in range(5)]
        hashes = [translog.leaf_hash(leaf) for leaf in leaf_objs]
        unsigned: dict[str, Any] = {
            "checkpoint_version": translog.CHECKPOINT_VERSION,
            "log_id": "did:web:registry.example.com/log/1",
            "tree_size": 5,
            "root_hash": translog.unparse_hash(translog.merkle_tree_hash(hashes)),
            "timestamp": "2026-07-04T12:00:00.000Z",
        }
        preimage = sha256_prefixed(jcs.canonicalize_any(unsigned))
        checkpoint = dict(unsigned)
        checkpoint["signature"] = {
            "algorithm": "ed25519",
            "key_id": "did:web:registry.example.com#log-key-1",
            "value": base64.b64encode(signing.sign_ed25519(self.SEED, preimage)).decode(),
        }
        inclusion = {
            "log_id": unsigned["log_id"],
            "leaf_index": 2,
            "tree_size": 5,
            "inclusion_path": [
                translog.unparse_hash(h) for h in translog.compute_inclusion_path(2, hashes)
            ],
        }
        return leaf_objs[2], checkpoint, inclusion

    def _check(self, **overrides: Any) -> translog.InclusionVerdict:
        leaf, checkpoint, inclusion = self._setup()
        kwargs: dict[str, Any] = {
            "log_checkpoint": checkpoint,
            "registry_public_key": signing.ed25519_public_key_from_seed(self.SEED),
            "leaf": leaf,
            "receipt_state": translog.ReceiptState.VERIFIED,
        }
        kwargs.update(overrides)
        return translog.verify_log_inclusion(inclusion, **kwargs)

    def test_included_with_verified_receipt(self) -> None:
        verdict = self._check()
        assert verdict.log_inclusion == "included"
        assert verdict.reason is None

    @pytest.mark.parametrize(
        ("state", "reason"),
        [
            (translog.ReceiptState.ABSENT, "receipt_absent"),
            (translog.ReceiptState.INVALID, "receipt_invalid"),
            (translog.ReceiptState.NOT_VERIFIED, "receipt_not_verified"),
        ],
    )
    def test_cannot_verify_without_verified_receipt(
        self, state: translog.ReceiptState, reason: str
    ) -> None:
        # Even a correct leaf is not used: without a verified receipt it
        # cannot have been reconstructed from verified material.
        verdict = self._check(receipt_state=state)
        assert verdict.log_inclusion == "cannot_verify"
        assert verdict.reason == reason

    def test_require_inclusion_fails_closed_as_invalid_receipt(self) -> None:
        with pytest.raises(InvalidReceipt):
            self._check(receipt_state=translog.ReceiptState.ABSENT, require_inclusion=True)

    def test_wrong_leaf_is_invalid_log_proof(self) -> None:
        with pytest.raises(InvalidLogProof):
            self._check(leaf=self._leaf(3))

    def test_binding_mismatch_is_invalid_log_proof(self) -> None:
        leaf, checkpoint, inclusion = self._setup()
        inclusion["tree_size"] = 4
        with pytest.raises(InvalidLogProof):
            translog.verify_log_inclusion(
                inclusion,
                log_checkpoint=checkpoint,
                registry_public_key=signing.ed25519_public_key_from_seed(self.SEED),
                leaf=leaf,
                receipt_state=translog.ReceiptState.VERIFIED,
            )

    def test_verified_receipt_requires_a_leaf(self) -> None:
        with pytest.raises(ValueError, match="reconstructed leaf"):
            self._check(leaf=None)

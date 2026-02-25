"""
Tests for Key Rotation Protocol

This module tests the key rotation implementation for secure key management.
"""

import unittest
import os
import secrets
import sys

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from encryption.key_rotation import (
    KeyRotationManager,
    RotationRequest,
    RotationStatus,
    ShareUpdateProof,
    RotationSecurityVerifier
)


class TestKeyRotationManager(unittest.TestCase):
    """Test cases for KeyRotationManager."""

    def setUp(self):
        """Set up test manager."""
        self.manager = KeyRotationManager()
        self.test_key = os.urandom(32)
        self.test_image_id = "IMG-TEST-001"

    def test_key_rotation_produces_different_key(self):
        """Test that rotation produces a different key."""
        new_key, metadata = self.manager.rotate_key(
            self.test_key, 0, self.test_image_id
        )

        self.assertNotEqual(self.test_key, new_key)
        self.assertEqual(len(new_key), 32)

    def test_rotation_is_deterministic(self):
        """Test that same inputs produce same output."""
        nonce = os.urandom(16)

        new_key1, _ = self.manager.rotate_key(
            self.test_key, 0, self.test_image_id, nonce
        )
        new_key2, _ = self.manager.rotate_key(
            self.test_key, 0, self.test_image_id, nonce
        )

        self.assertEqual(new_key1, new_key2)

    def test_different_epochs_different_keys(self):
        """Test that different epochs produce different keys."""
        nonce = os.urandom(16)

        key1, _ = self.manager.rotate_key(self.test_key, 0, self.test_image_id, nonce)
        key2, _ = self.manager.rotate_key(self.test_key, 1, self.test_image_id, nonce)

        self.assertNotEqual(key1, key2)

    def test_different_images_different_keys(self):
        """Test that different image IDs produce different keys."""
        nonce = os.urandom(16)

        key1, _ = self.manager.rotate_key(self.test_key, 0, "IMG-001", nonce)
        key2, _ = self.manager.rotate_key(self.test_key, 0, "IMG-002", nonce)

        self.assertNotEqual(key1, key2)

    def test_metadata_contains_required_fields(self):
        """Test that metadata contains all required fields."""
        _, metadata = self.manager.rotate_key(
            self.test_key, 0, self.test_image_id
        )

        required_fields = [
            'old_key_hash', 'new_key_hash', 'epoch', 'new_epoch',
            'image_id', 'nonce', 'timestamp', 'algorithm'
        ]

        for field in required_fields:
            self.assertIn(field, metadata)

        self.assertEqual(metadata['algorithm'], 'HKDF-SHA256')
        self.assertEqual(metadata['epoch'], 0)
        self.assertEqual(metadata['new_epoch'], 1)


class TestShareUpdate(unittest.TestCase):
    """Test share update functionality."""

    def setUp(self):
        """Set up test manager."""
        self.manager = KeyRotationManager()

    def test_share_update_is_reversible(self):
        """Test that share updates can be verified."""
        original_share = secrets.randbelow(self.manager.prime)
        epoch = 1

        new_share, update_factor = self.manager.update_share_locally(
            original_share, epoch
        )

        # Verify the update
        is_valid = self.manager.verify_share_update(original_share, new_share, epoch)
        self.assertTrue(is_valid)

    def test_different_epochs_different_factors(self):
        """Test that different epochs use different update factors."""
        factor1 = self.manager.compute_share_update_factor(1)
        factor2 = self.manager.compute_share_update_factor(2)

        self.assertNotEqual(factor1, factor2)

    def test_update_factor_is_nonzero(self):
        """Test that update factor is never zero."""
        for epoch in range(100):
            factor = self.manager.compute_share_update_factor(epoch)
            self.assertNotEqual(factor, 0)

    def test_batch_update_shares(self):
        """Test batch share update."""
        shares = [
            (1, secrets.randbelow(self.manager.prime)),
            (2, secrets.randbelow(self.manager.prime)),
            (3, secrets.randbelow(self.manager.prime))
        ]
        epoch = 1

        results = self.manager.batch_update_shares(shares, epoch)

        self.assertEqual(len(results), 3)
        for share_id, old_value, new_value in results:
            self.assertTrue(
                self.manager.verify_share_update(old_value, new_value, epoch)
            )

    def test_inverse_factor_correctness(self):
        """Test that inverse factor correctly reverses update."""
        original_share = secrets.randbelow(self.manager.prime)
        epoch = 1

        # Update
        new_share, _ = self.manager.update_share_locally(original_share, epoch)

        # Compute inverse
        inverse_factor = self.manager.compute_inverse_factor(epoch)

        # Apply inverse
        recovered_share = (new_share * inverse_factor) % self.manager.prime

        self.assertEqual(original_share, recovered_share)


class TestRotationWorkflow(unittest.TestCase):
    """Test the complete rotation workflow."""

    def setUp(self):
        """Set up test manager."""
        self.manager = KeyRotationManager()
        self.test_image_id = "IMG-WORKFLOW-001"
        self.test_key = os.urandom(32)

    def test_initiate_rotation(self):
        """Test rotation initiation."""
        request = self.manager.initiate_rotation(
            self.test_image_id, "initiator", required_approvals=2
        )

        self.assertEqual(request.status, RotationStatus.INITIATED)
        self.assertEqual(request.image_id, self.test_image_id)
        self.assertEqual(request.old_epoch, 0)
        self.assertEqual(request.new_epoch, 1)
        self.assertEqual(request.required_approvals, 2)
        self.assertEqual(len(request.approvals), 0)

    def test_approve_rotation(self):
        """Test rotation approval."""
        request = self.manager.initiate_rotation(
            self.test_image_id, "initiator", required_approvals=2
        )

        # First approval
        result1 = self.manager.approve_rotation(request, "approver1")
        self.assertTrue(result1)
        self.assertEqual(request.status, RotationStatus.PENDING_APPROVAL)
        self.assertEqual(len(request.approvals), 1)

        # Second approval
        result2 = self.manager.approve_rotation(request, "approver2")
        self.assertTrue(result2)
        self.assertEqual(request.status, RotationStatus.APPROVED)
        self.assertEqual(len(request.approvals), 2)

    def test_initiator_cannot_approve(self):
        """Test that initiator cannot approve their own rotation."""
        request = self.manager.initiate_rotation(
            self.test_image_id, "initiator", required_approvals=1
        )

        result = self.manager.approve_rotation(request, "initiator")
        self.assertFalse(result)

    def test_duplicate_approval_rejected(self):
        """Test that same party cannot approve twice."""
        request = self.manager.initiate_rotation(
            self.test_image_id, "initiator", required_approvals=2
        )

        result1 = self.manager.approve_rotation(request, "approver1")
        self.assertTrue(result1)

        result2 = self.manager.approve_rotation(request, "approver1")
        self.assertFalse(result2)

    def test_finalize_rotation(self):
        """Test rotation finalization."""
        request = self.manager.initiate_rotation(
            self.test_image_id, "initiator", required_approvals=2
        )

        self.manager.approve_rotation(request, "approver1")
        self.manager.approve_rotation(request, "approver2")

        new_key, metadata = self.manager.finalize_rotation(request, self.test_key)

        self.assertEqual(request.status, RotationStatus.FINALIZED)
        self.assertIsNotNone(request.new_key_hash)
        self.assertIsNotNone(request.completed_at)
        self.assertEqual(self.manager.get_current_epoch(self.test_image_id), 1)

    def test_cannot_finalize_unapproved(self):
        """Test that unapproved rotation cannot be finalized."""
        request = self.manager.initiate_rotation(
            self.test_image_id, "initiator", required_approvals=2
        )

        # Only one approval
        self.manager.approve_rotation(request, "approver1")

        with self.assertRaises(ValueError):
            self.manager.finalize_rotation(request, self.test_key)


class TestSecurityProperties(unittest.TestCase):
    """Test security properties of key rotation."""

    def setUp(self):
        """Set up test manager."""
        self.manager = KeyRotationManager()

    def test_forward_secrecy(self):
        """Test forward secrecy property."""
        old_key = os.urandom(32)
        new_key, metadata = self.manager.rotate_key(
            old_key, 0, "IMG-001"
        )

        result = self.manager.verify_forward_secrecy(old_key, new_key, metadata)
        self.assertTrue(result)

    def test_key_independence(self):
        """Test that successive keys appear independent."""
        verifier = RotationSecurityVerifier()
        base_key = os.urandom(32)

        result = verifier.verify_key_independence(
            self.manager, base_key, "TEST-001", num_rotations=10
        )
        self.assertTrue(result)

    def test_share_consistency(self):
        """Test share update consistency."""
        verifier = RotationSecurityVerifier()

        test_shares = [
            (i, secrets.randbelow(self.manager.prime))
            for i in range(1, 6)
        ]

        result = verifier.verify_share_consistency(
            self.manager, test_shares, num_epochs=5
        )
        self.assertTrue(result)


class TestRotationHistory(unittest.TestCase):
    """Test rotation history tracking."""

    def setUp(self):
        """Set up test manager."""
        self.manager = KeyRotationManager()

    def test_rotation_history_recorded(self):
        """Test that rotations are recorded in history."""
        image_id = "IMG-HISTORY-001"

        request = self.manager.initiate_rotation(image_id, "initiator")

        history = self.manager.get_rotation_history(image_id)
        self.assertEqual(len(history), 1)
        self.assertEqual(history[0].request_id, request.request_id)

    def test_get_all_history(self):
        """Test getting all rotation history."""
        self.manager.initiate_rotation("IMG-001", "initiator")
        self.manager.initiate_rotation("IMG-002", "initiator")

        all_history = self.manager.get_rotation_history()
        self.assertGreaterEqual(len(all_history), 2)

    def test_share_update_proof(self):
        """Test share update proof recording."""
        image_id = "IMG-PROOF-001"
        old_share = 12345
        new_share = 67890
        epoch = 1

        proof = self.manager.record_share_update_proof(
            image_id, 1, "holder1", old_share, new_share, epoch
        )

        self.assertEqual(proof.share_id, 1)
        self.assertEqual(proof.holder_id, "holder1")
        self.assertEqual(proof.epoch, epoch)
        self.assertIsNotNone(proof.old_share_hash)
        self.assertIsNotNone(proof.new_share_hash)


if __name__ == '__main__':
    unittest.main()

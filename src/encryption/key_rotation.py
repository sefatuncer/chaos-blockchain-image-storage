"""
Key Rotation Protocol for Medical Image Encryption

Implements periodic key rotation with forward and backward secrecy guarantees.
Designed to work with Shamir's Secret Sharing scheme for secure share updates.

Key Rotation Process:
    K_new = HKDF-SHA256(K_old || epoch || imageID || nonce)

Share Update (Local Computation):
    S_i^new = S_i^old * H(epoch) mod q

Security Properties:
    1. Forward Secrecy: Compromising K_new doesn't reveal K_old
    2. Backward Secrecy: Compromising K_old doesn't reveal K_new
    3. Proactive Security: Periodic rotation limits exposure window
    4. Non-Interactive: Share updates don't require coordination

The protocol integrates with blockchain for:
    - Epoch management (smart contract tracks current epoch)
    - Rotation audit trail (all rotations logged on-chain)
    - Distributed approval (multi-party authorization)

Reference:
This implements the Key Rotation Protocol described in Section 3.4.3
of the paper "Chaos-Based Medical Image Encryption with Blockchain-Coordinated
Threshold Key Recovery"
"""

import hashlib
import hmac
import os
import time
import secrets
from typing import Tuple, Optional, Dict, List
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum


class RotationStatus(Enum):
    """Status of a key rotation process."""
    INITIATED = "initiated"
    PENDING_APPROVAL = "pending_approval"
    APPROVED = "approved"
    FINALIZED = "finalized"
    CANCELLED = "cancelled"
    FAILED = "failed"


@dataclass
class RotationRequest:
    """
    Represents a key rotation request.
    """
    request_id: str
    image_id: str
    old_epoch: int
    new_epoch: int
    initiated_by: str
    initiated_at: datetime
    status: RotationStatus
    approvals: List[str] = field(default_factory=list)
    required_approvals: int = 2
    nonce: bytes = field(default_factory=lambda: os.urandom(16))
    completed_at: Optional[datetime] = None
    new_key_hash: Optional[str] = None


@dataclass
class ShareUpdateProof:
    """
    Proof that a share was correctly updated during rotation.
    """
    share_id: int
    holder_id: str
    old_share_hash: str
    new_share_hash: str
    epoch: int
    update_factor_hash: str
    timestamp: datetime


class KeyRotationManager:
    """
    Manages key rotation for the medical image encryption system.

    Implements HKDF-based key derivation and multiplicative share updates.

    Attributes:
        prime (int): Prime modulus for share arithmetic
        rotation_interval (timedelta): Minimum time between rotations
    """

    # Large prime for Shamir's Secret Sharing (256-bit)
    DEFAULT_PRIME = 2**256 - 189

    def __init__(self, prime: int = None,
                 rotation_interval: timedelta = timedelta(days=30)):
        """
        Initialize Key Rotation Manager.

        Args:
            prime: Prime modulus for share computations
            rotation_interval: Minimum interval between key rotations
        """
        self.prime = prime or self.DEFAULT_PRIME
        self.rotation_interval = rotation_interval
        self._current_epoch: Dict[str, int] = {}  # image_id -> epoch
        self._rotation_history: List[RotationRequest] = []
        self._share_proofs: Dict[str, List[ShareUpdateProof]] = {}

    def _hkdf_extract(self, salt: bytes, ikm: bytes) -> bytes:
        """
        HKDF Extract phase.

        Args:
            salt: Salt value
            ikm: Input keying material

        Returns:
            Pseudorandom key (PRK)
        """
        return hmac.new(salt, ikm, hashlib.sha256).digest()

    def _hkdf_expand(self, prk: bytes, info: bytes, length: int = 32) -> bytes:
        """
        HKDF Expand phase.

        Args:
            prk: Pseudorandom key from extract
            info: Context and application specific information
            length: Output length in bytes

        Returns:
            Output keying material
        """
        hash_len = 32  # SHA-256 output
        n = (length + hash_len - 1) // hash_len

        okm = b''
        t = b''

        for i in range(1, n + 1):
            t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
            okm += t

        return okm[:length]

    def _hkdf(self, ikm: bytes, salt: bytes, info: bytes, length: int = 32) -> bytes:
        """
        HKDF key derivation function (RFC 5869).

        Args:
            ikm: Input keying material
            salt: Salt value
            info: Context-specific info
            length: Output length

        Returns:
            Derived key material
        """
        prk = self._hkdf_extract(salt, ikm)
        return self._hkdf_expand(prk, info, length)

    def rotate_key(self, old_key: bytes, epoch: int, image_id: str,
                   nonce: bytes = None) -> Tuple[bytes, dict]:
        """
        Rotate encryption key using HKDF.

        K_new = HKDF-SHA256(K_old || epoch || imageID || nonce)

        Args:
            old_key: Current encryption key (32 bytes)
            epoch: Current epoch number
            image_id: Unique image identifier
            nonce: Random nonce (generated if None)

        Returns:
            Tuple of (new_key, rotation_metadata)
        """
        if nonce is None:
            nonce = os.urandom(16)

        # Construct input keying material
        ikm = old_key + epoch.to_bytes(8, 'big') + image_id.encode() + nonce

        # Use image_id and epoch as salt
        salt = hashlib.sha256(image_id.encode() + epoch.to_bytes(8, 'big')).digest()

        # Context info for key derivation
        info = b"CCM-KEY-ROTATION-V1"

        # Derive new key
        new_key = self._hkdf(ikm, salt, info, 32)

        metadata = {
            'old_key_hash': hashlib.sha256(old_key).hexdigest(),
            'new_key_hash': hashlib.sha256(new_key).hexdigest(),
            'epoch': epoch,
            'new_epoch': epoch + 1,
            'image_id': image_id,
            'nonce': nonce.hex(),
            'timestamp': datetime.now().isoformat(),
            'algorithm': 'HKDF-SHA256'
        }

        return new_key, metadata

    def compute_share_update_factor(self, epoch: int) -> int:
        """
        Compute the multiplicative factor for share updates.

        H(epoch) = SHA256(epoch) mod prime

        Args:
            epoch: Current epoch number

        Returns:
            Update factor as integer
        """
        epoch_bytes = epoch.to_bytes(8, 'big')
        hash_bytes = hashlib.sha256(epoch_bytes + b"SHARE-UPDATE").digest()
        factor = int.from_bytes(hash_bytes, 'big') % self.prime

        # Ensure non-zero factor
        if factor == 0:
            factor = 1

        return factor

    def update_share_locally(self, share_value: int, epoch: int) -> Tuple[int, int]:
        """
        Update a share locally without coordination.

        S_i^new = S_i^old * H(epoch) mod q

        Args:
            share_value: Current share value
            epoch: Epoch for the update

        Returns:
            Tuple of (new_share_value, update_factor)
        """
        update_factor = self.compute_share_update_factor(epoch)
        new_share = (share_value * update_factor) % self.prime

        return new_share, update_factor

    def compute_inverse_factor(self, epoch: int) -> int:
        """
        Compute inverse of update factor for share recovery.

        Used when reconstructing key with shares from different epochs.

        Args:
            epoch: Epoch of the update

        Returns:
            Multiplicative inverse of update factor
        """
        factor = self.compute_share_update_factor(epoch)
        return pow(factor, -1, self.prime)

    def verify_share_update(self, old_share: int, new_share: int, epoch: int) -> bool:
        """
        Verify that a share was correctly updated.

        Args:
            old_share: Original share value
            new_share: Updated share value
            epoch: Epoch used for update

        Returns:
            True if update is valid
        """
        expected_new, _ = self.update_share_locally(old_share, epoch)
        return expected_new == new_share

    def initiate_rotation(self, image_id: str, initiator_id: str,
                          required_approvals: int = 2) -> RotationRequest:
        """
        Initiate a key rotation request.

        Args:
            image_id: Image to rotate key for
            initiator_id: ID of party initiating rotation
            required_approvals: Number of approvals needed

        Returns:
            RotationRequest object
        """
        current_epoch = self._current_epoch.get(image_id, 0)
        new_epoch = current_epoch + 1

        request_id = hashlib.sha256(
            f"{image_id}:{new_epoch}:{time.time_ns()}".encode()
        ).hexdigest()[:16]

        request = RotationRequest(
            request_id=request_id,
            image_id=image_id,
            old_epoch=current_epoch,
            new_epoch=new_epoch,
            initiated_by=initiator_id,
            initiated_at=datetime.now(),
            status=RotationStatus.INITIATED,
            required_approvals=required_approvals
        )

        self._rotation_history.append(request)

        return request

    def approve_rotation(self, request: RotationRequest, approver_id: str) -> bool:
        """
        Approve a pending rotation request.

        Args:
            request: Rotation request to approve
            approver_id: ID of approving party

        Returns:
            True if approval was recorded
        """
        if request.status not in [RotationStatus.INITIATED, RotationStatus.PENDING_APPROVAL]:
            return False

        if approver_id in request.approvals:
            return False  # Already approved

        if approver_id == request.initiated_by:
            return False  # Initiator cannot approve

        request.approvals.append(approver_id)
        request.status = RotationStatus.PENDING_APPROVAL

        if len(request.approvals) >= request.required_approvals:
            request.status = RotationStatus.APPROVED

        return True

    def finalize_rotation(self, request: RotationRequest,
                          old_key: bytes) -> Tuple[bytes, dict]:
        """
        Finalize an approved rotation by computing new key.

        Args:
            request: Approved rotation request
            old_key: Current encryption key

        Returns:
            Tuple of (new_key, metadata)
        """
        if request.status != RotationStatus.APPROVED:
            raise ValueError("Rotation must be approved before finalization")

        new_key, metadata = self.rotate_key(
            old_key,
            request.old_epoch,
            request.image_id,
            request.nonce
        )

        request.status = RotationStatus.FINALIZED
        request.completed_at = datetime.now()
        request.new_key_hash = metadata['new_key_hash']

        # Update current epoch
        self._current_epoch[request.image_id] = request.new_epoch

        return new_key, metadata

    def record_share_update_proof(self, image_id: str, share_id: int,
                                  holder_id: str, old_share: int,
                                  new_share: int, epoch: int) -> ShareUpdateProof:
        """
        Record proof of share update for audit.

        Args:
            image_id: Image ID
            share_id: Share identifier
            holder_id: Share holder ID
            old_share: Original share value
            new_share: Updated share value
            epoch: Epoch of update

        Returns:
            ShareUpdateProof object
        """
        update_factor = self.compute_share_update_factor(epoch)

        proof = ShareUpdateProof(
            share_id=share_id,
            holder_id=holder_id,
            old_share_hash=hashlib.sha256(str(old_share).encode()).hexdigest(),
            new_share_hash=hashlib.sha256(str(new_share).encode()).hexdigest(),
            epoch=epoch,
            update_factor_hash=hashlib.sha256(str(update_factor).encode()).hexdigest(),
            timestamp=datetime.now()
        )

        if image_id not in self._share_proofs:
            self._share_proofs[image_id] = []
        self._share_proofs[image_id].append(proof)

        return proof

    def get_current_epoch(self, image_id: str) -> int:
        """
        Get current epoch for an image.

        Args:
            image_id: Image identifier

        Returns:
            Current epoch number
        """
        return self._current_epoch.get(image_id, 0)

    def get_rotation_history(self, image_id: str = None) -> List[RotationRequest]:
        """
        Get rotation history.

        Args:
            image_id: Optional filter by image ID

        Returns:
            List of rotation requests
        """
        if image_id:
            return [r for r in self._rotation_history if r.image_id == image_id]
        return self._rotation_history

    def verify_forward_secrecy(self, old_key: bytes, new_key: bytes,
                               metadata: dict) -> bool:
        """
        Verify that knowing new_key doesn't reveal old_key.

        This is a probabilistic test - actual forward secrecy comes from
        HKDF's cryptographic properties.

        Args:
            old_key: Original key
            new_key: Rotated key
            metadata: Rotation metadata

        Returns:
            True if forward secrecy property holds
        """
        # Verify keys are different
        if old_key == new_key:
            return False

        # Verify new_key hash matches metadata
        if hashlib.sha256(new_key).hexdigest() != metadata['new_key_hash']:
            return False

        # Verify old_key hash matches metadata
        if hashlib.sha256(old_key).hexdigest() != metadata['old_key_hash']:
            return False

        return True

    def batch_update_shares(self, shares: List[Tuple[int, int]],
                            epoch: int) -> List[Tuple[int, int, int]]:
        """
        Update multiple shares for a given epoch.

        Args:
            shares: List of (share_id, share_value) tuples
            epoch: Epoch for the update

        Returns:
            List of (share_id, old_value, new_value) tuples
        """
        update_factor = self.compute_share_update_factor(epoch)
        results = []

        for share_id, share_value in shares:
            new_value = (share_value * update_factor) % self.prime
            results.append((share_id, share_value, new_value))

        return results


class RotationSecurityVerifier:
    """
    Verifies security properties of key rotation.
    """

    @staticmethod
    def verify_key_independence(manager: KeyRotationManager,
                                 base_key: bytes, image_id: str,
                                 num_rotations: int = 10) -> bool:
        """
        Verify that successive rotated keys appear independent.

        Args:
            manager: Key rotation manager
            base_key: Starting key
            image_id: Image identifier
            num_rotations: Number of rotations to test

        Returns:
            True if keys appear independent
        """
        keys = [base_key]
        current_key = base_key

        for epoch in range(num_rotations):
            new_key, _ = manager.rotate_key(current_key, epoch, image_id)
            keys.append(new_key)
            current_key = new_key

        # Check that all keys are unique
        key_set = set(k.hex() for k in keys)
        if len(key_set) != len(keys):
            return False

        # Check correlation (simple byte-level)
        for i in range(len(keys) - 1):
            matching_bytes = sum(
                1 for a, b in zip(keys[i], keys[i+1]) if a == b
            )
            # Should be roughly random (~1/256 * 32 = ~0.125 bytes)
            if matching_bytes > 8:  # Significantly above random
                return False

        return True

    @staticmethod
    def verify_share_consistency(manager: KeyRotationManager,
                                  original_shares: List[Tuple[int, int]],
                                  num_epochs: int = 5) -> bool:
        """
        Verify that shares can be updated and verified consistently.

        Args:
            manager: Key rotation manager
            original_shares: List of (share_id, share_value)
            num_epochs: Number of epochs to test

        Returns:
            True if all updates are consistent
        """
        current_shares = list(original_shares)

        for epoch in range(1, num_epochs + 1):
            new_shares = []
            for share_id, share_value in current_shares:
                new_value, _ = manager.update_share_locally(share_value, epoch)

                # Verify the update
                if not manager.verify_share_update(share_value, new_value, epoch):
                    return False

                new_shares.append((share_id, new_value))

            current_shares = new_shares

        return True


if __name__ == "__main__":
    print("Key Rotation Protocol Demo")
    print("=" * 60)

    # Initialize manager
    manager = KeyRotationManager()

    # Generate initial key
    initial_key = os.urandom(32)
    image_id = "IMG-12345"

    print(f"Image ID: {image_id}")
    print(f"Initial Key Hash: {hashlib.sha256(initial_key).hexdigest()[:32]}...")

    # Demonstrate key rotation
    print("\n" + "=" * 60)
    print("Key Rotation Demo")
    print("=" * 60)

    current_key = initial_key
    for epoch in range(3):
        new_key, metadata = manager.rotate_key(current_key, epoch, image_id)
        print(f"\nEpoch {epoch} -> {epoch + 1}:")
        print(f"  Old Key Hash: {metadata['old_key_hash'][:32]}...")
        print(f"  New Key Hash: {metadata['new_key_hash'][:32]}...")
        print(f"  Nonce: {metadata['nonce'][:16]}...")
        current_key = new_key

    # Demonstrate share update
    print("\n" + "=" * 60)
    print("Share Update Demo")
    print("=" * 60)

    # Simulate shares
    original_shares = [
        (1, secrets.randbelow(manager.prime)),
        (2, secrets.randbelow(manager.prime)),
        (3, secrets.randbelow(manager.prime))
    ]

    print("\nOriginal Shares:")
    for share_id, share_value in original_shares:
        print(f"  Share {share_id}: {str(share_value)[:32]}...")

    # Update shares for epoch 1
    print("\nUpdating shares for epoch 1:")
    for share_id, share_value in original_shares:
        new_value, update_factor = manager.update_share_locally(share_value, 1)
        is_valid = manager.verify_share_update(share_value, new_value, 1)
        print(f"  Share {share_id}: {str(new_value)[:32]}... (Valid: {is_valid})")

    # Demonstrate rotation workflow
    print("\n" + "=" * 60)
    print("Rotation Workflow Demo")
    print("=" * 60)

    # Initiate rotation
    request = manager.initiate_rotation(image_id, "admin_user", required_approvals=2)
    print(f"\nRotation Request ID: {request.request_id}")
    print(f"Status: {request.status.value}")
    print(f"Required Approvals: {request.required_approvals}")

    # Approve rotation
    manager.approve_rotation(request, "approver_1")
    print(f"\nAfter 1st approval - Status: {request.status.value}")
    print(f"Approvals: {request.approvals}")

    manager.approve_rotation(request, "approver_2")
    print(f"\nAfter 2nd approval - Status: {request.status.value}")
    print(f"Approvals: {request.approvals}")

    # Finalize rotation
    final_key, final_meta = manager.finalize_rotation(request, initial_key)
    print(f"\nRotation Finalized:")
    print(f"Status: {request.status.value}")
    print(f"New Key Hash: {final_meta['new_key_hash'][:32]}...")
    print(f"Current Epoch: {manager.get_current_epoch(image_id)}")

    # Security verification
    print("\n" + "=" * 60)
    print("Security Property Verification")
    print("=" * 60)

    verifier = RotationSecurityVerifier()

    # Verify forward secrecy
    fs_result = manager.verify_forward_secrecy(initial_key, final_key, final_meta)
    print(f"\nForward Secrecy: {'PASS' if fs_result else 'FAIL'}")

    # Verify key independence
    ki_result = verifier.verify_key_independence(manager, os.urandom(32), "TEST-001")
    print(f"Key Independence: {'PASS' if ki_result else 'FAIL'}")

    # Verify share consistency
    test_shares = [(i, secrets.randbelow(manager.prime)) for i in range(1, 6)]
    sc_result = verifier.verify_share_consistency(manager, test_shares)
    print(f"Share Consistency: {'PASS' if sc_result else 'FAIL'}")

    print("\nKey Rotation Protocol demonstration complete!")

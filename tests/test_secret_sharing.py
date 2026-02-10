"""
Unit Tests for Shamir's Secret Sharing

Tests the (k,n) threshold secret sharing implementation.
"""

import pytest
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from src.secret_sharing import ShamirSecretSharing


class TestShamirSecretSharing:
    """Tests for Shamir's Secret Sharing implementation."""

    def test_basic_split_reconstruct(self):
        """Test basic secret splitting and reconstruction."""
        sss = ShamirSecretSharing(threshold=3, num_shares=5)
        secret = b"This is a secret key!"

        shares = sss.split_secret(secret)
        assert len(shares) == 5

        recovered = sss.reconstruct_secret(shares[:3])
        assert recovered == secret

    def test_threshold_combinations(self):
        """Test that any k shares can reconstruct the secret."""
        sss = ShamirSecretSharing(threshold=3, num_shares=5)
        secret = b"Test secret 123"

        shares = sss.split_secret(secret)

        # Test different combinations
        combinations = [
            [shares[0], shares[1], shares[2]],  # First 3
            [shares[2], shares[3], shares[4]],  # Last 3
            [shares[0], shares[2], shares[4]],  # Alternating
        ]

        for combo in combinations:
            recovered = sss.reconstruct_secret(combo)
            assert recovered == secret

    def test_insufficient_shares(self):
        """Test that fewer than k shares cannot reconstruct."""
        sss = ShamirSecretSharing(threshold=3, num_shares=5)
        secret = b"Test secret"

        shares = sss.split_secret(secret)

        with pytest.raises(ValueError):
            sss.reconstruct_secret(shares[:2])  # Only 2 shares

    def test_hex_encoding(self):
        """Test hex-encoded secret sharing."""
        sss = ShamirSecretSharing(threshold=3, num_shares=5)
        secret_hex = "deadbeef1234567890"

        shares = sss.split_secret_hex(secret_hex)
        assert len(shares) == 5
        assert all(isinstance(s[1], str) for s in shares)

        recovered_hex = sss.reconstruct_secret_hex(shares[:3])
        assert recovered_hex == secret_hex

    def test_large_secret(self):
        """Test with a larger secret."""
        sss = ShamirSecretSharing(threshold=3, num_shares=5)
        secret = os.urandom(32)  # 256-bit random key

        shares = sss.split_secret(secret)
        recovered = sss.reconstruct_secret(shares[:3])

        assert recovered == secret

    def test_verify_shares(self):
        """Test share verification."""
        sss = ShamirSecretSharing(threshold=3, num_shares=5)
        secret = b"Verification test"

        shares = sss.split_secret(secret)
        assert sss.verify_shares(shares)

    def test_invalid_threshold(self):
        """Test invalid threshold parameters."""
        with pytest.raises(ValueError):
            ShamirSecretSharing(threshold=6, num_shares=5)

        with pytest.raises(ValueError):
            ShamirSecretSharing(threshold=1, num_shares=5)

    def test_minimum_shares(self):
        """Test (2,2) threshold scheme."""
        sss = ShamirSecretSharing(threshold=2, num_shares=2)
        secret = b"Minimal test"

        shares = sss.split_secret(secret)
        assert len(shares) == 2

        recovered = sss.reconstruct_secret(shares)
        assert recovered == secret


class TestKeyShareManager:
    """Tests for the KeyShareManager class."""

    def test_key_share_generation(self):
        """Test encryption key share generation."""
        from src.secret_sharing.shamir import KeyShareManager

        manager = KeyShareManager(threshold=3, num_shares=5)

        encryption_key = {
            'seed': 12345678901234567890,
            'iterations': 10,
            'hash': 'abc123def456'
        }

        packages = manager.generate_key_shares(encryption_key)

        assert len(packages) == 5
        assert all('share_id' in pkg for pkg in packages)
        assert all('x' in pkg for pkg in packages)
        assert all('y_hex' in pkg for pkg in packages)

    def test_key_recovery(self):
        """Test encryption key recovery from shares."""
        from src.secret_sharing.shamir import KeyShareManager

        manager = KeyShareManager(threshold=3, num_shares=5)

        encryption_key = {
            'seed': 98765432109876543210,
            'iterations': 15,
            'hash': 'xyz789'
        }

        packages = manager.generate_key_shares(encryption_key)
        recovered_key = manager.recover_key(packages[:3])

        assert recovered_key['seed'] == encryption_key['seed']
        assert recovered_key['iterations'] == encryption_key['iterations']


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

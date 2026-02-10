"""
Unit Tests for Chaotic Cat Map Encryption

Tests the CCM encryption implementation for both grayscale and color images.
"""

import pytest
import numpy as np
from PIL import Image
import tempfile
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from src.encryption import ChaoticCatMapEncryption, ColorImageEncryption


class TestChaoticCatMapEncryption:
    """Tests for grayscale image encryption."""

    @pytest.fixture
    def sample_image(self):
        """Create a sample test image."""
        img = np.zeros((64, 64), dtype=np.uint8)
        for i in range(64):
            for j in range(64):
                img[i, j] = int(128 + 60 * np.sin(i/10) * np.cos(j/12))

        with tempfile.NamedTemporaryFile(suffix='.png', delete=False) as f:
            Image.fromarray(img).save(f.name)
            yield f.name
        os.unlink(f.name)

    def test_encryption_decryption(self, sample_image):
        """Test that encryption followed by decryption returns original."""
        ccm = ChaoticCatMapEncryption(iterations=5)
        encrypted, key = ccm.encrypt(sample_image)
        decrypted = ccm.decrypt(encrypted, key)

        original = np.array(Image.open(sample_image).convert('L'))
        original = original[:decrypted.shape[0], :decrypted.shape[1]]

        assert np.array_equal(original, decrypted)

    def test_entropy_increase(self, sample_image):
        """Test that encryption increases entropy."""
        ccm = ChaoticCatMapEncryption(iterations=10)
        encrypted, _ = ccm.encrypt(sample_image)

        original = np.array(Image.open(sample_image).convert('L'))

        original_entropy = ccm.calculate_entropy(original)
        encrypted_entropy = ccm.calculate_entropy(encrypted)

        # Encrypted should have higher entropy (closer to 8)
        assert encrypted_entropy > original_entropy
        assert encrypted_entropy > 7.9  # Should be close to maximum

    def test_correlation_reduction(self, sample_image):
        """Test that encryption reduces pixel correlation."""
        ccm = ChaoticCatMapEncryption(iterations=10)
        encrypted, _ = ccm.encrypt(sample_image)

        original = np.array(Image.open(sample_image).convert('L'))

        orig_corr = abs(ccm.calculate_correlation(original, 'horizontal'))
        enc_corr = abs(ccm.calculate_correlation(encrypted, 'horizontal'))

        # Encrypted should have lower correlation
        assert enc_corr < orig_corr
        assert enc_corr < 0.1  # Should be close to 0

    def test_npcr_uaci(self, sample_image):
        """Test NPCR and UACI metrics."""
        ccm = ChaoticCatMapEncryption(iterations=10)
        encrypted, _ = ccm.encrypt(sample_image)

        original = np.array(Image.open(sample_image).convert('L'))
        # Resize original to match encrypted
        original = original[:encrypted.shape[0], :encrypted.shape[1]]

        npcr, uaci = ccm.calculate_npcr_uaci(original, encrypted)

        # NPCR should be close to 99.6%
        assert npcr > 99.0

        # UACI should be close to 33.46%
        assert 30 < uaci < 40

    def test_different_seeds(self, sample_image):
        """Test that different seeds produce different results."""
        ccm1 = ChaoticCatMapEncryption(iterations=5, seed=12345)
        ccm2 = ChaoticCatMapEncryption(iterations=5, seed=67890)

        encrypted1, _ = ccm1.encrypt(sample_image)
        encrypted2, _ = ccm2.encrypt(sample_image)

        assert not np.array_equal(encrypted1, encrypted2)


class TestColorImageEncryption:
    """Tests for color image encryption."""

    @pytest.fixture
    def sample_color_image(self):
        """Create a sample color test image."""
        img = np.zeros((64, 64, 3), dtype=np.uint8)
        for i in range(64):
            for j in range(64):
                img[i, j, 0] = int(128 + 60 * np.sin(i/10))
                img[i, j, 1] = int(128 + 60 * np.cos(j/12))
                img[i, j, 2] = int(128 + 60 * np.sin((i+j)/15))

        with tempfile.NamedTemporaryFile(suffix='.png', delete=False) as f:
            Image.fromarray(img).save(f.name)
            yield f.name
        os.unlink(f.name)

    def test_color_encryption_decryption(self, sample_color_image):
        """Test color image encryption and decryption."""
        ccm = ColorImageEncryption(iterations=5)
        encrypted, key = ccm.encrypt(sample_color_image)
        decrypted = ccm.decrypt(encrypted, key)

        original = np.array(Image.open(sample_color_image).convert('RGB'))
        original = original[:decrypted.shape[0], :decrypted.shape[1], :]

        assert np.array_equal(original, decrypted)

    def test_channel_independence(self, sample_color_image):
        """Test that each channel is encrypted independently."""
        ccm = ColorImageEncryption(iterations=5)
        encrypted, key = ccm.encrypt(sample_color_image)

        # Check that channel seeds are different
        assert key['channel_seeds']['R'] != key['channel_seeds']['G']
        assert key['channel_seeds']['G'] != key['channel_seeds']['B']

    def test_color_entropy(self, sample_color_image):
        """Test entropy for each color channel."""
        ccm = ColorImageEncryption(iterations=10)
        encrypted, _ = ccm.encrypt(sample_color_image)

        r_ent, g_ent, b_ent, avg_ent = ccm.calculate_entropy(encrypted)

        # Each channel should have high entropy
        assert r_ent > 7.9
        assert g_ent > 7.9
        assert b_ent > 7.9
        assert avg_ent > 7.9


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

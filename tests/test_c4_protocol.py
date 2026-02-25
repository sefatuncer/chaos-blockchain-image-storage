"""
Tests for Cross-Channel Chaotic Coupling (C4) Protocol

This module tests the C4 protocol implementation for color image encryption.
"""

import unittest
import numpy as np
from PIL import Image
import os
import sys
import tempfile

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from encryption.c4_protocol import CrossChannelChaoticCoupling, compare_c4_vs_independent


class TestC4Protocol(unittest.TestCase):
    """Test cases for C4 Protocol."""

    @classmethod
    def setUpClass(cls):
        """Create test images."""
        cls.temp_dir = tempfile.mkdtemp()

        # Create test color image
        cls.test_image = np.zeros((128, 128, 3), dtype=np.uint8)
        for i in range(128):
            for j in range(128):
                cls.test_image[i, j, 0] = int(128 + 60 * np.sin(i/20))
                cls.test_image[i, j, 1] = int(128 + 60 * np.cos(j/25))
                cls.test_image[i, j, 2] = int(128 + 60 * np.sin((i+j)/30))

        cls.test_image_path = os.path.join(cls.temp_dir, "test_color.png")
        Image.fromarray(cls.test_image).save(cls.test_image_path)

    @classmethod
    def tearDownClass(cls):
        """Clean up test files."""
        if os.path.exists(cls.test_image_path):
            os.remove(cls.test_image_path)
        os.rmdir(cls.temp_dir)

    def test_encrypt_decrypt_roundtrip(self):
        """Test that encryption followed by decryption returns original."""
        c4 = CrossChannelChaoticCoupling(iterations=5)
        encrypted, metadata = c4.encrypt_c4(self.test_image_path)
        decrypted = c4.decrypt_c4(encrypted, metadata)

        original = np.array(Image.open(self.test_image_path).convert('RGB'))
        original = original[:decrypted.shape[0], :decrypted.shape[1], :]

        self.assertTrue(np.array_equal(original, decrypted))

    def test_encryption_changes_image(self):
        """Test that encryption produces different output."""
        c4 = CrossChannelChaoticCoupling(iterations=5)
        encrypted, _ = c4.encrypt_c4(self.test_image_path)

        original = np.array(Image.open(self.test_image_path).convert('RGB'))

        self.assertFalse(np.array_equal(original, encrypted))

    def test_different_keys_different_results(self):
        """Test that different keys produce different ciphertexts."""
        key1 = os.urandom(32)
        key2 = os.urandom(32)

        c4_1 = CrossChannelChaoticCoupling(iterations=5, master_key=key1)
        c4_2 = CrossChannelChaoticCoupling(iterations=5, master_key=key2)

        encrypted1, _ = c4_1.encrypt_c4(self.test_image_path)
        encrypted2, _ = c4_2.encrypt_c4(self.test_image_path)

        self.assertFalse(np.array_equal(encrypted1, encrypted2))

    def test_same_key_same_result(self):
        """Test deterministic encryption with same key."""
        key = os.urandom(32)

        c4_1 = CrossChannelChaoticCoupling(iterations=5, master_key=key)
        c4_2 = CrossChannelChaoticCoupling(iterations=5, master_key=key)

        encrypted1, _ = c4_1.encrypt_c4(self.test_image_path)
        encrypted2, _ = c4_2.encrypt_c4(self.test_image_path)

        self.assertTrue(np.array_equal(encrypted1, encrypted2))

    def test_metadata_contains_required_fields(self):
        """Test that metadata contains all required fields."""
        c4 = CrossChannelChaoticCoupling(iterations=5)
        _, metadata = c4.encrypt_c4(self.test_image_path)

        required_fields = [
            'master_key', 'iterations', 'image_salt', 'original_size',
            'original_hash', 'encrypted_hash', 'algorithm', 'version',
            'cross_channel_hashes', 'channel_metadata'
        ]

        for field in required_fields:
            self.assertIn(field, metadata)

        self.assertEqual(metadata['algorithm'], 'C4-ECCM')

    def test_inter_channel_correlation_reduction(self):
        """Test that C4 reduces inter-channel correlation."""
        c4 = CrossChannelChaoticCoupling(iterations=10)
        encrypted, _ = c4.encrypt_c4(self.test_image_path)

        original = np.array(Image.open(self.test_image_path).convert('RGB'))

        orig_corr = c4.calculate_inter_channel_correlation(original)
        enc_corr = c4.calculate_inter_channel_correlation(encrypted)

        # Encrypted should have lower correlation
        self.assertLess(abs(enc_corr['mean_abs']), abs(orig_corr['mean_abs']) + 0.1)

    def test_cross_channel_avalanche(self):
        """Test cross-channel avalanche effect."""
        c4 = CrossChannelChaoticCoupling(iterations=10)
        avalanche = c4.cross_channel_avalanche_test(self.test_image_path)

        # Change in R should affect all channels
        self.assertGreater(avalanche['R_change_affects_R'], 30)
        # Cross-channel effect should be significant due to C4 coupling
        self.assertGreater(avalanche['total_avalanche'], 20)

    def test_entropy_near_maximum(self):
        """Test that encrypted image has high entropy."""
        c4 = CrossChannelChaoticCoupling(iterations=10)
        encrypted, _ = c4.encrypt_c4(self.test_image_path)

        # Calculate entropy for each channel
        for channel in range(3):
            channel_data = encrypted[:, :, channel]
            hist, _ = np.histogram(channel_data.flatten(), bins=256, range=(0, 256))
            hist = hist / hist.sum()
            hist = hist[hist > 0]
            entropy = -np.sum(hist * np.log2(hist))

            # Entropy should be close to 8 (maximum for 8-bit)
            self.assertGreater(entropy, 7.5)


class TestC4Comparison(unittest.TestCase):
    """Test C4 vs independent channel comparison."""

    @classmethod
    def setUpClass(cls):
        """Create test image."""
        cls.temp_dir = tempfile.mkdtemp()

        test_image = np.zeros((64, 64, 3), dtype=np.uint8)
        for i in range(64):
            for j in range(64):
                test_image[i, j, 0] = int(128 + 60 * np.sin(i/10))
                test_image[i, j, 1] = int(128 + 60 * np.cos(j/12))
                test_image[i, j, 2] = int(128 + 60 * np.sin((i+j)/15))

        cls.test_image_path = os.path.join(cls.temp_dir, "test_compare.png")
        Image.fromarray(test_image).save(cls.test_image_path)

    @classmethod
    def tearDownClass(cls):
        """Clean up."""
        if os.path.exists(cls.test_image_path):
            os.remove(cls.test_image_path)
        os.rmdir(cls.temp_dir)

    def test_comparison_function(self):
        """Test that comparison function works."""
        comparison = compare_c4_vs_independent(self.test_image_path)

        self.assertIn('c4_protocol', comparison)
        self.assertIn('independent', comparison)
        self.assertIn('improvement', comparison)

        self.assertEqual(comparison['c4_protocol']['algorithm'], 'C4-ECCM')
        self.assertEqual(comparison['independent']['algorithm'], 'ECCM-Independent')


if __name__ == '__main__':
    unittest.main()

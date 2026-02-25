"""
Cross-Channel Chaotic Coupling (C4) Protocol

A novel color image encryption protocol that introduces cross-channel
dependencies to prevent single-channel cryptanalysis attacks.

Standard color image encryption encrypts R, G, B channels independently,
which may leak information if an attacker can isolate and analyze
individual channels. C4 Protocol addresses this by coupling channels:

C4 Encryption Process:
    R' = CCM(R, K_R XOR SHA256(G || B))
    G' = CCM(G, K_G XOR SHA256(R' || B))
    B' = CCM(B, K_B XOR SHA256(R' || G'))

C4 Decryption Process (reverse order):
    B  = CCM_inv(B', K_B XOR SHA256(R' || G'))
    G  = CCM_inv(G', K_G XOR SHA256(R' || B))
    R  = CCM_inv(R', K_R XOR SHA256(G || B))

Security Properties:
1. Channel Interdependence: Each encrypted channel depends on other channels
2. Sequential Coupling: Creates a chain where compromising one channel
   requires knowledge of others
3. Key Mixing: Channel keys are XORed with cross-channel hashes
4. Avalanche Effect: Change in any channel affects all encrypted channels

Reference:
This implements the C4 Protocol described in Section 3.2.3 of the paper
"Chaos-Based Medical Image Encryption with Blockchain-Coordinated
Threshold Key Recovery"
"""

import numpy as np
from PIL import Image
import hashlib
import os
from typing import Tuple, Optional, Dict
from .eccm_encryption import EnhancedChaoticCatMap


class CrossChannelChaoticCoupling:
    """
    Cross-Channel Chaotic Coupling (C4) Protocol for color image encryption.

    Provides enhanced security over standard independent channel encryption
    by introducing cross-channel dependencies during encryption.

    Attributes:
        iterations (int): Number of CCM iterations per channel
        master_key (bytes): 256-bit master encryption key
    """

    def __init__(self, iterations: int = 10, master_key: bytes = None):
        """
        Initialize C4 Protocol encryptor.

        Args:
            iterations: Number of permutation-diffusion rounds per channel
            master_key: 256-bit (32 bytes) master key, randomly generated if None
        """
        self.iterations = iterations

        if master_key is None:
            self.master_key = os.urandom(32)
        else:
            if len(master_key) < 32:
                self.master_key = hashlib.sha256(master_key).digest()
            else:
                self.master_key = master_key[:32]

    def _derive_channel_key(self, channel: str) -> bytes:
        """
        Derive base key for a specific channel.

        Args:
            channel: Channel identifier ('R', 'G', or 'B')

        Returns:
            32-byte channel-specific key
        """
        data = self.master_key + channel.encode() + b'C4-BASE'
        return hashlib.sha256(data).digest()

    def _xor_keys(self, key1: bytes, key2: bytes) -> bytes:
        """
        XOR two byte sequences.

        Args:
            key1: First key
            key2: Second key

        Returns:
            XORed result
        """
        return bytes(a ^ b for a, b in zip(key1, key2))

    def _compute_cross_channel_hash(self, channel1: np.ndarray,
                                    channel2: np.ndarray) -> bytes:
        """
        Compute SHA-256 hash of two concatenated channels.

        Args:
            channel1: First channel array
            channel2: Second channel array

        Returns:
            32-byte hash
        """
        combined = channel1.tobytes() + channel2.tobytes()
        return hashlib.sha256(combined).digest()

    def _encrypt_channel(self, channel: np.ndarray, key: bytes,
                         image_salt: bytes) -> Tuple[np.ndarray, dict]:
        """
        Encrypt a single channel using ECCM.

        Args:
            channel: Channel array to encrypt
            key: Encryption key
            image_salt: Salt derived from image

        Returns:
            Tuple of (encrypted_channel, metadata)
        """
        # Create ECCM encryptor with the derived key
        encryptor = EnhancedChaoticCatMap(
            iterations=self.iterations,
            master_key=key
        )

        N = channel.shape[0]
        encrypted = channel.copy()

        for round_num in range(self.iterations):
            round_key = encryptor._derive_round_key(round_num, image_salt)
            a, b, c, d = encryptor._derive_matrix_params(round_key, N)
            encrypted = encryptor._key_dependent_cat_map(encrypted, a, b, c, d)
            chaos_seq = encryptor._generate_chaotic_sequence(
                encrypted.size, round_key, image_salt
            )
            encrypted = encryptor._bidirectional_diffusion(encrypted, chaos_seq)

        metadata = {
            'key': key.hex(),
            'salt': image_salt.hex()
        }

        return encrypted, metadata

    def _decrypt_channel(self, encrypted: np.ndarray, key: bytes,
                         image_salt: bytes) -> np.ndarray:
        """
        Decrypt a single channel using ECCM.

        Args:
            encrypted: Encrypted channel array
            key: Decryption key
            image_salt: Salt used during encryption

        Returns:
            Decrypted channel
        """
        encryptor = EnhancedChaoticCatMap(
            iterations=self.iterations,
            master_key=key
        )

        N = encrypted.shape[0]
        decrypted = encrypted.copy()

        # Reconstruct round parameters
        round_params = []
        for round_num in range(self.iterations):
            round_key = encryptor._derive_round_key(round_num, image_salt)
            a, b, c, d = encryptor._derive_matrix_params(round_key, N)
            round_params.append((a, b, c, d, round_key))

        # Decrypt in reverse order
        for round_num in range(self.iterations - 1, -1, -1):
            a, b, c, d, round_key = round_params[round_num]
            chaos_seq = encryptor._generate_chaotic_sequence(
                decrypted.size, round_key, image_salt
            )
            decrypted = encryptor._inverse_bidirectional_diffusion(decrypted, chaos_seq)
            decrypted = encryptor._inverse_cat_map(decrypted, a, b, c, d)

        return decrypted

    def encrypt_c4(self, image_path: str) -> Tuple[np.ndarray, dict]:
        """
        Encrypt a color image using C4 Protocol.

        The encryption follows cross-channel coupling:
        R' = CCM(R, K_R XOR SHA256(G || B))
        G' = CCM(G, K_G XOR SHA256(R' || B))
        B' = CCM(B, K_B XOR SHA256(R' || G'))

        Args:
            image_path: Path to input color image

        Returns:
            Tuple of (encrypted_image, encryption_metadata)
        """
        # Load and prepare image
        img = Image.open(image_path).convert('RGB')
        size = min(img.size)
        img = img.resize((size, size))
        image_array = np.array(img, dtype=np.uint8)

        # Extract channels
        R = image_array[:, :, 0]
        G = image_array[:, :, 1]
        B = image_array[:, :, 2]

        # Compute image salt from original image
        image_salt = hashlib.sha256(image_array.tobytes()).digest()

        # Get base channel keys
        K_R = self._derive_channel_key('R')
        K_G = self._derive_channel_key('G')
        K_B = self._derive_channel_key('B')

        # C4 Protocol Encryption

        # Step 1: R' = CCM(R, K_R XOR SHA256(G || B))
        cross_hash_GB = self._compute_cross_channel_hash(G, B)
        K_R_coupled = self._xor_keys(K_R, cross_hash_GB)
        R_encrypted, R_meta = self._encrypt_channel(R, K_R_coupled, image_salt)

        # Step 2: G' = CCM(G, K_G XOR SHA256(R' || B))
        cross_hash_RB = self._compute_cross_channel_hash(R_encrypted, B)
        K_G_coupled = self._xor_keys(K_G, cross_hash_RB)
        G_encrypted, G_meta = self._encrypt_channel(G, K_G_coupled, image_salt)

        # Step 3: B' = CCM(B, K_B XOR SHA256(R' || G'))
        cross_hash_RG = self._compute_cross_channel_hash(R_encrypted, G_encrypted)
        K_B_coupled = self._xor_keys(K_B, cross_hash_RG)
        B_encrypted, B_meta = self._encrypt_channel(B, K_B_coupled, image_salt)

        # Combine encrypted channels
        encrypted = np.zeros_like(image_array)
        encrypted[:, :, 0] = R_encrypted
        encrypted[:, :, 1] = G_encrypted
        encrypted[:, :, 2] = B_encrypted

        # Create comprehensive metadata
        metadata = {
            'master_key': self.master_key.hex(),
            'iterations': self.iterations,
            'image_salt': image_salt.hex(),
            'original_size': img.size,
            'original_hash': hashlib.sha256(image_array.tobytes()).hexdigest(),
            'encrypted_hash': hashlib.sha256(encrypted.tobytes()).hexdigest(),
            'algorithm': 'C4-ECCM',
            'version': '1.0',
            'cross_channel_hashes': {
                'GB': cross_hash_GB.hex(),
                'RB': cross_hash_RB.hex(),
                'RG': cross_hash_RG.hex()
            },
            'channel_metadata': {
                'R': R_meta,
                'G': G_meta,
                'B': B_meta
            }
        }

        return encrypted, metadata

    def decrypt_c4(self, encrypted_image: np.ndarray, metadata: dict) -> np.ndarray:
        """
        Decrypt a C4-encrypted color image.

        Decryption follows reverse order:
        B  = CCM_inv(B', K_B XOR SHA256(R' || G'))
        G  = CCM_inv(G', K_G XOR SHA256(R' || B))
        R  = CCM_inv(R', K_R XOR SHA256(G || B))

        Args:
            encrypted_image: Encrypted image array (H x W x 3)
            metadata: Encryption metadata from encrypt_c4()

        Returns:
            Decrypted original image
        """
        # Restore parameters
        self.master_key = bytes.fromhex(metadata['master_key'])
        self.iterations = metadata['iterations']
        image_salt = bytes.fromhex(metadata['image_salt'])

        # Get base channel keys
        K_R = self._derive_channel_key('R')
        K_G = self._derive_channel_key('G')
        K_B = self._derive_channel_key('B')

        # Extract encrypted channels
        R_encrypted = encrypted_image[:, :, 0]
        G_encrypted = encrypted_image[:, :, 1]
        B_encrypted = encrypted_image[:, :, 2]

        # C4 Protocol Decryption (reverse order)

        # Step 1: B = CCM_inv(B', K_B XOR SHA256(R' || G'))
        cross_hash_RG = self._compute_cross_channel_hash(R_encrypted, G_encrypted)
        K_B_coupled = self._xor_keys(K_B, cross_hash_RG)
        B = self._decrypt_channel(B_encrypted, K_B_coupled, image_salt)

        # Step 2: G = CCM_inv(G', K_G XOR SHA256(R' || B))
        cross_hash_RB = self._compute_cross_channel_hash(R_encrypted, B)
        K_G_coupled = self._xor_keys(K_G, cross_hash_RB)
        G = self._decrypt_channel(G_encrypted, K_G_coupled, image_salt)

        # Step 3: R = CCM_inv(R', K_R XOR SHA256(G || B))
        cross_hash_GB = self._compute_cross_channel_hash(G, B)
        K_R_coupled = self._xor_keys(K_R, cross_hash_GB)
        R = self._decrypt_channel(R_encrypted, K_R_coupled, image_salt)

        # Combine decrypted channels
        decrypted = np.zeros_like(encrypted_image)
        decrypted[:, :, 0] = R
        decrypted[:, :, 1] = G
        decrypted[:, :, 2] = B

        return decrypted

    def save_encrypted(self, encrypted: np.ndarray, output_path: str) -> None:
        """Save encrypted image to file."""
        Image.fromarray(encrypted).save(output_path)

    def calculate_inter_channel_correlation(self, image: np.ndarray,
                                           samples: int = 5000) -> Dict[str, float]:
        """
        Calculate inter-channel correlation coefficients.

        Low correlation between encrypted channels indicates good
        cross-channel security.

        Args:
            image: Color image array
            samples: Number of random samples

        Returns:
            Dictionary with R-G, R-B, G-B correlations
        """
        h, w = image.shape[:2]

        x_pos = np.random.randint(0, w, samples)
        y_pos = np.random.randint(0, h, samples)

        R = image[y_pos, x_pos, 0].astype(float)
        G = image[y_pos, x_pos, 1].astype(float)
        B = image[y_pos, x_pos, 2].astype(float)

        rg_corr = np.corrcoef(R, G)[0, 1]
        rb_corr = np.corrcoef(R, B)[0, 1]
        gb_corr = np.corrcoef(G, B)[0, 1]

        return {
            'R-G': rg_corr,
            'R-B': rb_corr,
            'G-B': gb_corr,
            'mean_abs': np.mean([abs(rg_corr), abs(rb_corr), abs(gb_corr)])
        }

    def cross_channel_avalanche_test(self, image_path: str) -> Dict[str, float]:
        """
        Test cross-channel avalanche effect.

        Measures how a single-pixel change in one channel affects
        all encrypted channels.

        Args:
            image_path: Path to test image

        Returns:
            Dictionary with avalanche metrics per channel
        """
        # Encrypt original
        encrypted1, meta = self.encrypt_c4(image_path)

        # Load and modify one pixel in R channel
        img = Image.open(image_path).convert('RGB')
        size = min(img.size)
        img = img.resize((size, size))
        img_array = np.array(img, dtype=np.uint8)

        # Flip one pixel in R channel
        img_array[0, 0, 0] = (img_array[0, 0, 0] + 1) % 256

        # Save modified image
        temp_path = '_temp_c4_avalanche.png'
        Image.fromarray(img_array).save(temp_path)

        # Create new encryptor with same key
        encryptor2 = CrossChannelChaoticCoupling(
            iterations=self.iterations,
            master_key=self.master_key
        )
        encrypted2, _ = encryptor2.encrypt_c4(temp_path)

        # Clean up
        os.remove(temp_path)

        # Calculate per-channel differences
        total_pixels = encrypted1[:, :, 0].size

        r_diff = np.sum(encrypted1[:, :, 0] != encrypted2[:, :, 0]) / total_pixels * 100
        g_diff = np.sum(encrypted1[:, :, 1] != encrypted2[:, :, 1]) / total_pixels * 100
        b_diff = np.sum(encrypted1[:, :, 2] != encrypted2[:, :, 2]) / total_pixels * 100

        return {
            'R_change_affects_R': r_diff,
            'R_change_affects_G': g_diff,
            'R_change_affects_B': b_diff,
            'total_avalanche': (r_diff + g_diff + b_diff) / 3
        }


def compare_c4_vs_independent(image_path: str) -> dict:
    """
    Compare C4 Protocol security metrics against independent channel encryption.

    Args:
        image_path: Path to test image

    Returns:
        Comparison dictionary with metrics for both methods
    """
    from .eccm_encryption import EnhancedColorEncryption

    # Common key for fair comparison
    test_key = os.urandom(32)

    # C4 Protocol encryption
    c4 = CrossChannelChaoticCoupling(iterations=10, master_key=test_key)
    c4_encrypted, c4_meta = c4.encrypt_c4(image_path)
    c4_corr = c4.calculate_inter_channel_correlation(c4_encrypted)

    # Independent channel encryption
    indep = EnhancedColorEncryption(iterations=10, master_key=test_key)
    indep_encrypted, indep_meta = indep.encrypt(image_path)

    # Calculate independent encryption correlation
    h, w = indep_encrypted.shape[:2]
    samples = 5000
    x_pos = np.random.randint(0, w, samples)
    y_pos = np.random.randint(0, h, samples)

    R = indep_encrypted[y_pos, x_pos, 0].astype(float)
    G = indep_encrypted[y_pos, x_pos, 1].astype(float)
    B = indep_encrypted[y_pos, x_pos, 2].astype(float)

    indep_corr = {
        'R-G': np.corrcoef(R, G)[0, 1],
        'R-B': np.corrcoef(R, B)[0, 1],
        'G-B': np.corrcoef(G, B)[0, 1]
    }
    indep_corr['mean_abs'] = np.mean([abs(indep_corr['R-G']),
                                       abs(indep_corr['R-B']),
                                       abs(indep_corr['G-B'])])

    return {
        'c4_protocol': {
            'inter_channel_correlation': c4_corr,
            'algorithm': 'C4-ECCM'
        },
        'independent': {
            'inter_channel_correlation': indep_corr,
            'algorithm': 'ECCM-Independent'
        },
        'improvement': {
            'correlation_reduction': indep_corr['mean_abs'] - c4_corr['mean_abs']
        }
    }


if __name__ == "__main__":
    print("Cross-Channel Chaotic Coupling (C4) Protocol Demo")
    print("=" * 60)

    # Create test color image
    test_image = np.zeros((256, 256, 3), dtype=np.uint8)
    for i in range(256):
        for j in range(256):
            test_image[i, j, 0] = int(128 + 60 * np.sin(i/30))
            test_image[i, j, 1] = int(128 + 60 * np.cos(j/35))
            test_image[i, j, 2] = int(128 + 60 * np.sin((i+j)/40))

    Image.fromarray(test_image).save("test_c4_original.png")

    # Encrypt with C4 Protocol
    c4 = CrossChannelChaoticCoupling(iterations=10)
    encrypted, metadata = c4.encrypt_c4("test_c4_original.png")
    c4.save_encrypted(encrypted, "test_c4_encrypted.png")

    print(f"Algorithm: {metadata['algorithm']}")
    print(f"Iterations: {metadata['iterations']}")
    print(f"Master Key: {metadata['master_key'][:32]}...")

    # Decrypt and verify
    decrypted = c4.decrypt_c4(encrypted, metadata)
    original = np.array(Image.open("test_c4_original.png").convert('RGB'))

    print(f"\nDecryption successful: {np.array_equal(original, decrypted)}")

    # Inter-channel correlation analysis
    print("\n" + "=" * 60)
    print("Inter-Channel Correlation Analysis")
    print("=" * 60)

    orig_corr = c4.calculate_inter_channel_correlation(original)
    enc_corr = c4.calculate_inter_channel_correlation(encrypted)

    print(f"\nOriginal Image Inter-Channel Correlation:")
    print(f"  R-G: {orig_corr['R-G']:.6f}")
    print(f"  R-B: {orig_corr['R-B']:.6f}")
    print(f"  G-B: {orig_corr['G-B']:.6f}")
    print(f"  Mean |corr|: {orig_corr['mean_abs']:.6f}")

    print(f"\nEncrypted Image Inter-Channel Correlation:")
    print(f"  R-G: {enc_corr['R-G']:.6f}")
    print(f"  R-B: {enc_corr['R-B']:.6f}")
    print(f"  G-B: {enc_corr['G-B']:.6f}")
    print(f"  Mean |corr|: {enc_corr['mean_abs']:.6f}")

    # Cross-channel avalanche test
    print("\n" + "=" * 60)
    print("Cross-Channel Avalanche Test")
    print("=" * 60)

    avalanche = c4.cross_channel_avalanche_test("test_c4_original.png")
    print(f"\nSingle pixel change in R channel affects:")
    print(f"  R channel: {avalanche['R_change_affects_R']:.2f}% pixels")
    print(f"  G channel: {avalanche['R_change_affects_G']:.2f}% pixels")
    print(f"  B channel: {avalanche['R_change_affects_B']:.2f}% pixels")
    print(f"  Total avalanche: {avalanche['total_avalanche']:.2f}%")

    # Comparison with independent encryption
    print("\n" + "=" * 60)
    print("C4 vs Independent Channel Encryption Comparison")
    print("=" * 60)

    comparison = compare_c4_vs_independent("test_c4_original.png")
    print(f"\nC4 Protocol mean |correlation|: "
          f"{comparison['c4_protocol']['inter_channel_correlation']['mean_abs']:.6f}")
    print(f"Independent mean |correlation|: "
          f"{comparison['independent']['inter_channel_correlation']['mean_abs']:.6f}")
    print(f"Correlation reduction: "
          f"{comparison['improvement']['correlation_reduction']:.6f}")

    # Cleanup
    os.remove("test_c4_original.png")
    os.remove("test_c4_encrypted.png")

    print("\nC4 Protocol demonstration complete!")

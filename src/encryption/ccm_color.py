"""
Chaotic Cat Map (CCM) Encryption for Color Images

Extension of CCM encryption for RGB color images, where each color
channel is encrypted independently.

Reference:
"Integration of Chaos-Based Encryption and Blockchain for Tamper-Proof
Medical Image Storage and Authentication"
"""

import numpy as np
from PIL import Image
import hashlib
import os
from typing import Tuple, Optional
from .ccm_encryption import ChaoticCatMapEncryption


class ColorImageEncryption:
    """
    Implements Chaotic Cat Map encryption for color (RGB) images.

    Each color channel (R, G, B) is encrypted independently using
    different seeds derived from a master key.

    Attributes:
        iterations (int): Number of Cat Map iterations per channel
        master_seed (int): Master seed for key derivation
    """

    def __init__(self, iterations: int = 10, master_seed: Optional[int] = None):
        """
        Initialize the color image encryptor.

        Args:
            iterations: Number of Arnold Cat Map iterations per channel
            master_seed: Optional master seed for key generation
        """
        self.iterations = iterations
        self.master_seed = master_seed if master_seed else self._generate_seed()

    def _generate_seed(self) -> int:
        """Generate a cryptographically secure random seed."""
        return int.from_bytes(os.urandom(4), byteorder='big')

    def _derive_channel_seeds(self) -> Tuple[int, int, int]:
        """
        Derive different seeds for each color channel.

        Uses SHA-256 hash of master seed to generate channel-specific seeds.

        Returns:
            Tuple of (red_seed, green_seed, blue_seed)
        """
        hash_input = str(self.master_seed).encode()

        red_hash = hashlib.sha256(hash_input + b'R').digest()
        green_hash = hashlib.sha256(hash_input + b'G').digest()
        blue_hash = hashlib.sha256(hash_input + b'B').digest()

        red_seed = int.from_bytes(red_hash[:4], byteorder='big')
        green_seed = int.from_bytes(green_hash[:4], byteorder='big')
        blue_seed = int.from_bytes(blue_hash[:4], byteorder='big')

        return red_seed, green_seed, blue_seed

    def encrypt(self, image_path: str) -> Tuple[np.ndarray, dict]:
        """
        Encrypt a color image using Chaotic Cat Map.

        Each RGB channel is encrypted independently with different keys.

        Args:
            image_path: Path to the input image

        Returns:
            Tuple of (encrypted_image, encryption_key)
        """
        # Load and prepare image
        img = Image.open(image_path).convert('RGB')

        # Resize to square if necessary
        size = min(img.size)
        img = img.resize((size, size))

        image_array = np.array(img, dtype=np.uint8)

        # Get channel-specific seeds
        r_seed, g_seed, b_seed = self._derive_channel_seeds()

        # Create encryptors for each channel
        r_encryptor = ChaoticCatMapEncryption(self.iterations, r_seed)
        g_encryptor = ChaoticCatMapEncryption(self.iterations, g_seed)
        b_encryptor = ChaoticCatMapEncryption(self.iterations, b_seed)

        # Encrypt each channel
        encrypted = np.zeros_like(image_array)

        # Red channel
        r_channel = image_array[:, :, 0]
        encrypted[:, :, 0] = self._encrypt_channel(r_channel, r_encryptor)

        # Green channel
        g_channel = image_array[:, :, 1]
        encrypted[:, :, 1] = self._encrypt_channel(g_channel, g_encryptor)

        # Blue channel
        b_channel = image_array[:, :, 2]
        encrypted[:, :, 2] = self._encrypt_channel(b_channel, b_encryptor)

        # Generate encryption key
        key = {
            'master_seed': self.master_seed,
            'channel_seeds': {
                'R': r_seed,
                'G': g_seed,
                'B': b_seed
            },
            'iterations': self.iterations,
            'original_size': img.size,
            'hash': hashlib.sha256(image_array.tobytes()).hexdigest()
        }

        return encrypted, key

    def _encrypt_channel(self, channel: np.ndarray,
                         encryptor: ChaoticCatMapEncryption) -> np.ndarray:
        """
        Encrypt a single color channel.

        Args:
            channel: Single channel (grayscale) array
            encryptor: Configured CCM encryptor

        Returns:
            Encrypted channel
        """
        encrypted = channel.copy()

        for _ in range(encryptor.iterations):
            encrypted = encryptor._arnold_cat_map(encrypted)
            encrypted = encryptor._diffuse(encrypted)

        return encrypted

    def decrypt(self, encrypted_image: np.ndarray, key: dict) -> np.ndarray:
        """
        Decrypt an encrypted color image.

        Args:
            encrypted_image: Encrypted image array
            key: Encryption key dictionary

        Returns:
            Decrypted image
        """
        self.master_seed = key['master_seed']
        self.iterations = key['iterations']

        channel_seeds = key['channel_seeds']

        # Create decryptors for each channel
        r_decryptor = ChaoticCatMapEncryption(self.iterations, channel_seeds['R'])
        g_decryptor = ChaoticCatMapEncryption(self.iterations, channel_seeds['G'])
        b_decryptor = ChaoticCatMapEncryption(self.iterations, channel_seeds['B'])

        # Decrypt each channel
        decrypted = np.zeros_like(encrypted_image)

        decrypted[:, :, 0] = self._decrypt_channel(encrypted_image[:, :, 0], r_decryptor)
        decrypted[:, :, 1] = self._decrypt_channel(encrypted_image[:, :, 1], g_decryptor)
        decrypted[:, :, 2] = self._decrypt_channel(encrypted_image[:, :, 2], b_decryptor)

        return decrypted

    def _decrypt_channel(self, channel: np.ndarray,
                         decryptor: ChaoticCatMapEncryption) -> np.ndarray:
        """
        Decrypt a single color channel.

        Args:
            channel: Encrypted channel array
            decryptor: Configured CCM decryptor

        Returns:
            Decrypted channel
        """
        decrypted = channel.copy()

        for _ in range(decryptor.iterations):
            decrypted = decryptor._inverse_diffuse(decrypted)
            decrypted = decryptor._inverse_arnold_cat_map(decrypted)

        return decrypted

    def save_encrypted(self, encrypted: np.ndarray, output_path: str) -> None:
        """Save encrypted color image to file."""
        Image.fromarray(encrypted).save(output_path)

    def calculate_entropy(self, image: np.ndarray) -> Tuple[float, float, float, float]:
        """
        Calculate Shannon entropy for each channel and average.

        Args:
            image: Color image array

        Returns:
            Tuple of (red_entropy, green_entropy, blue_entropy, average)
        """
        entropies = []

        for c in range(3):
            channel = image[:, :, c]
            histogram, _ = np.histogram(channel.flatten(), bins=256, range=(0, 256))
            histogram = histogram / histogram.sum()
            histogram = histogram[histogram > 0]
            entropy = -np.sum(histogram * np.log2(histogram))
            entropies.append(entropy)

        avg_entropy = np.mean(entropies)

        return entropies[0], entropies[1], entropies[2], avg_entropy

    def calculate_correlation(self, image: np.ndarray,
                             direction: str = 'horizontal',
                             samples: int = 5000) -> Tuple[float, float, float, float]:
        """
        Calculate correlation coefficient for each channel.

        Args:
            image: Color image array
            direction: 'horizontal', 'vertical', or 'diagonal'
            samples: Number of sample pairs

        Returns:
            Tuple of (R_corr, G_corr, B_corr, average)
        """
        correlations = []
        h, w = image.shape[:2]

        for c in range(3):
            channel = image[:, :, c].astype(float)

            if direction == 'horizontal':
                x1 = np.random.randint(0, w - 1, samples)
                y1 = np.random.randint(0, h, samples)
                p1 = channel[y1, x1]
                p2 = channel[y1, x1 + 1]
            elif direction == 'vertical':
                x1 = np.random.randint(0, w, samples)
                y1 = np.random.randint(0, h - 1, samples)
                p1 = channel[y1, x1]
                p2 = channel[y1 + 1, x1]
            else:  # diagonal
                x1 = np.random.randint(0, w - 1, samples)
                y1 = np.random.randint(0, h - 1, samples)
                p1 = channel[y1, x1]
                p2 = channel[y1 + 1, x1 + 1]

            corr = np.corrcoef(p1, p2)[0, 1]
            correlations.append(corr)

        avg_corr = np.mean(correlations)

        return correlations[0], correlations[1], correlations[2], avg_corr

    def calculate_npcr_uaci(self, image1: np.ndarray,
                           image2: np.ndarray) -> Tuple[float, float]:
        """
        Calculate NPCR and UACI for color images (averaged across channels).

        Args:
            image1: First image
            image2: Second image

        Returns:
            Tuple of (NPCR, UACI) in percentage
        """
        npcr_values = []
        uaci_values = []

        for c in range(3):
            c1 = image1[:, :, c]
            c2 = image2[:, :, c]

            diff = (c1 != c2).astype(float)
            npcr = np.mean(diff) * 100
            npcr_values.append(npcr)

            uaci = np.mean(np.abs(c1.astype(float) - c2.astype(float)) / 255) * 100
            uaci_values.append(uaci)

        return np.mean(npcr_values), np.mean(uaci_values)


if __name__ == "__main__":
    # Example usage for color images
    print("Color Image CCM Encryption Demo")
    print("=" * 50)

    # Create a sample color image for testing
    test_image = np.zeros((256, 256, 3), dtype=np.uint8)
    for i in range(256):
        for j in range(256):
            test_image[i, j, 0] = int(128 + 60 * np.sin(i/30))  # Red
            test_image[i, j, 1] = int(128 + 60 * np.cos(j/35))  # Green
            test_image[i, j, 2] = int(128 + 60 * np.sin((i+j)/40))  # Blue

    Image.fromarray(test_image).save("test_color_original.png")

    # Encrypt
    color_ccm = ColorImageEncryption(iterations=10)
    encrypted, key = color_ccm.encrypt("test_color_original.png")
    color_ccm.save_encrypted(encrypted, "test_color_encrypted.png")

    print(f"Master Seed: {key['master_seed']}")
    print(f"Channel Seeds: R={key['channel_seeds']['R']}, "
          f"G={key['channel_seeds']['G']}, B={key['channel_seeds']['B']}")

    # Calculate metrics
    original = np.array(Image.open("test_color_original.png").convert('RGB'))

    r_ent, g_ent, b_ent, avg_ent = color_ccm.calculate_entropy(encrypted)
    print(f"\nEncrypted Entropy: R={r_ent:.4f}, G={g_ent:.4f}, B={b_ent:.4f}, Avg={avg_ent:.4f}")

    r_corr, g_corr, b_corr, avg_corr = color_ccm.calculate_correlation(encrypted, 'horizontal')
    print(f"Horizontal Correlation: R={r_corr:.4f}, G={g_corr:.4f}, B={b_corr:.4f}, Avg={avg_corr:.4f}")

    npcr, uaci = color_ccm.calculate_npcr_uaci(original, encrypted)
    print(f"\nNPCR: {npcr:.2f}%")
    print(f"UACI: {uaci:.2f}%")

    # Decrypt and verify
    decrypted = color_ccm.decrypt(encrypted, key)
    print(f"\nDecryption successful: {np.array_equal(original, decrypted)}")

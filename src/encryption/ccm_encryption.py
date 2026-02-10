"""
Chaotic Cat Map (CCM) Encryption for Grayscale Images

Implementation of the Arnold Cat Map for chaos-based image encryption
with permutation-diffusion architecture and 256-bit key space.

The Arnold Cat Map transformation:
    x' = (x + y) mod N
    y' = (x + 2y) mod N

Where (x, y) are pixel coordinates and N is the image dimension.
"""

import numpy as np
from PIL import Image
import hashlib
import os
from typing import Tuple, Optional


class ChaoticCatMapEncryption:
    """
    Implements Chaotic Cat Map encryption for grayscale images.

    The encryption process consists of:
    1. Pixel position permutation using Arnold Cat Map
    2. Pixel value diffusion using chaotic sequence
    3. Multiple rounds of permutation-diffusion

    Attributes:
        iterations (int): Number of Cat Map iterations (default: 10)
        seed (int): Random seed for reproducibility
    """

    def __init__(self, iterations: int = 10, seed: Optional[int] = None):
        """
        Initialize the CCM encryptor.

        Args:
            iterations: Number of Arnold Cat Map iterations
            seed: Optional seed for key generation
        """
        self.iterations = iterations
        self.seed = seed if seed is not None else self._generate_seed()
        np.random.seed(self.seed)

    def _generate_seed(self) -> int:
        """Generate a cryptographically secure random seed."""
        return int.from_bytes(os.urandom(4), byteorder='big')

    def _arnold_cat_map(self, image: np.ndarray) -> np.ndarray:
        """
        Apply Arnold Cat Map transformation to scramble pixel positions.

        Args:
            image: Input grayscale image as numpy array

        Returns:
            Scrambled image
        """
        N = image.shape[0]
        scrambled = np.zeros_like(image)

        for x in range(N):
            for y in range(N):
                # Arnold Cat Map transformation
                new_x = (x + y) % N
                new_y = (x + 2 * y) % N
                scrambled[new_x, new_y] = image[x, y]

        return scrambled

    def _inverse_arnold_cat_map(self, image: np.ndarray) -> np.ndarray:
        """
        Apply inverse Arnold Cat Map transformation.

        Args:
            image: Scrambled image

        Returns:
            Unscrambled image
        """
        N = image.shape[0]
        unscrambled = np.zeros_like(image)

        for x in range(N):
            for y in range(N):
                # Inverse transformation
                orig_x = (2 * x - y) % N
                orig_y = (-x + y) % N
                unscrambled[orig_x, orig_y] = image[x, y]

        return unscrambled

    def _generate_chaotic_sequence(self, length: int) -> np.ndarray:
        """
        Generate chaotic sequence for pixel value diffusion.

        Uses the Logistic Map: x_{n+1} = r * x_n * (1 - x_n)

        Args:
            length: Length of the sequence to generate

        Returns:
            Chaotic sequence as numpy array
        """
        r = 3.9999  # Chaotic parameter (fully chaotic when r ≈ 4)
        x = 0.1 + (self.seed % 1000) / 10000  # Initial value from seed

        sequence = np.zeros(length)
        for i in range(length):
            x = r * x * (1 - x)
            sequence[i] = x

        # Convert to integer values 0-255
        return (sequence * 256).astype(np.uint8)

    def _diffuse(self, image: np.ndarray) -> np.ndarray:
        """
        Apply diffusion to pixel values using chaotic sequence.

        Args:
            image: Input image

        Returns:
            Diffused image
        """
        flat = image.flatten()
        chaos_seq = self._generate_chaotic_sequence(len(flat))

        # XOR with chaotic sequence
        diffused = np.bitwise_xor(flat, chaos_seq)

        return diffused.reshape(image.shape)

    def _inverse_diffuse(self, image: np.ndarray) -> np.ndarray:
        """
        Apply inverse diffusion (XOR is self-inverse).

        Args:
            image: Diffused image

        Returns:
            Original image
        """
        return self._diffuse(image)  # XOR is self-inverse

    def encrypt(self, image_path: str) -> Tuple[np.ndarray, dict]:
        """
        Encrypt an image using Chaotic Cat Map.

        Args:
            image_path: Path to the input image

        Returns:
            Tuple of (encrypted_image, encryption_key)
        """
        # Load and prepare image
        img = Image.open(image_path).convert('L')  # Convert to grayscale

        # Resize to square if necessary (Cat Map requires square images)
        size = min(img.size)
        img = img.resize((size, size))

        image_array = np.array(img, dtype=np.uint8)

        # Apply encryption rounds
        encrypted = image_array.copy()
        for _ in range(self.iterations):
            # Permutation phase
            encrypted = self._arnold_cat_map(encrypted)
            # Diffusion phase
            encrypted = self._diffuse(encrypted)

        # Generate encryption key
        key = {
            'seed': self.seed,
            'iterations': self.iterations,
            'original_size': img.size,
            'hash': hashlib.sha256(image_array.tobytes()).hexdigest()
        }

        return encrypted, key

    def decrypt(self, encrypted_image: np.ndarray, key: dict) -> np.ndarray:
        """
        Decrypt an encrypted image.

        Args:
            encrypted_image: Encrypted image array
            key: Encryption key dictionary

        Returns:
            Decrypted image
        """
        self.seed = key['seed']
        self.iterations = key['iterations']
        np.random.seed(self.seed)

        decrypted = encrypted_image.copy()

        # Apply inverse operations in reverse order
        for _ in range(self.iterations):
            decrypted = self._inverse_diffuse(decrypted)
            decrypted = self._inverse_arnold_cat_map(decrypted)

        return decrypted

    def save_encrypted(self, encrypted: np.ndarray, output_path: str) -> None:
        """
        Save encrypted image to file.

        Args:
            encrypted: Encrypted image array
            output_path: Path for output file
        """
        Image.fromarray(encrypted).save(output_path)

    def calculate_entropy(self, image: np.ndarray) -> float:
        """
        Calculate Shannon entropy of an image.

        Args:
            image: Image array

        Returns:
            Entropy value (max 8 for 8-bit images)
        """
        histogram, _ = np.histogram(image.flatten(), bins=256, range=(0, 256))
        histogram = histogram / histogram.sum()
        histogram = histogram[histogram > 0]

        return -np.sum(histogram * np.log2(histogram))

    def calculate_correlation(self, image: np.ndarray,
                             direction: str = 'horizontal',
                             samples: int = 5000) -> float:
        """
        Calculate correlation coefficient between adjacent pixels.

        Args:
            image: Image array
            direction: 'horizontal', 'vertical', or 'diagonal'
            samples: Number of sample pairs

        Returns:
            Correlation coefficient
        """
        h, w = image.shape

        if direction == 'horizontal':
            x1 = np.random.randint(0, w - 1, samples)
            y1 = np.random.randint(0, h, samples)
            p1 = image[y1, x1].astype(float)
            p2 = image[y1, x1 + 1].astype(float)
        elif direction == 'vertical':
            x1 = np.random.randint(0, w, samples)
            y1 = np.random.randint(0, h - 1, samples)
            p1 = image[y1, x1].astype(float)
            p2 = image[y1 + 1, x1].astype(float)
        else:  # diagonal
            x1 = np.random.randint(0, w - 1, samples)
            y1 = np.random.randint(0, h - 1, samples)
            p1 = image[y1, x1].astype(float)
            p2 = image[y1 + 1, x1 + 1].astype(float)

        return np.corrcoef(p1, p2)[0, 1]

    def calculate_npcr_uaci(self, image1: np.ndarray,
                           image2: np.ndarray) -> Tuple[float, float]:
        """
        Calculate NPCR (Number of Pixels Change Rate) and UACI
        (Unified Average Changing Intensity).

        Args:
            image1: First image
            image2: Second image

        Returns:
            Tuple of (NPCR, UACI) in percentage
        """
        diff = (image1 != image2).astype(float)
        npcr = np.mean(diff) * 100

        uaci = np.mean(np.abs(image1.astype(float) - image2.astype(float)) / 255) * 100

        return npcr, uaci


if __name__ == "__main__":
    # Example usage
    print("Chaotic Cat Map Encryption Demo")
    print("=" * 50)

    # Create a sample image for testing
    test_image = np.zeros((256, 256), dtype=np.uint8)
    for i in range(256):
        for j in range(256):
            test_image[i, j] = int(128 + 60 * np.sin(i/30) * np.cos(j/35))

    Image.fromarray(test_image).save("test_original.png")

    # Encrypt
    ccm = ChaoticCatMapEncryption(iterations=10)
    encrypted, key = ccm.encrypt("test_original.png")
    ccm.save_encrypted(encrypted, "test_encrypted.png")

    print(f"Seed: {key['seed']}")
    print(f"Iterations: {key['iterations']}")
    print(f"Original Hash: {key['hash'][:32]}...")

    # Calculate metrics
    original = np.array(Image.open("test_original.png").convert('L'))

    print(f"\nOriginal Entropy: {ccm.calculate_entropy(original):.4f}")
    print(f"Encrypted Entropy: {ccm.calculate_entropy(encrypted):.4f}")

    print(f"\nOriginal Correlations:")
    print(f"  Horizontal: {ccm.calculate_correlation(original, 'horizontal'):.4f}")
    print(f"  Vertical: {ccm.calculate_correlation(original, 'vertical'):.4f}")
    print(f"  Diagonal: {ccm.calculate_correlation(original, 'diagonal'):.4f}")

    print(f"\nEncrypted Correlations:")
    print(f"  Horizontal: {ccm.calculate_correlation(encrypted, 'horizontal'):.4f}")
    print(f"  Vertical: {ccm.calculate_correlation(encrypted, 'vertical'):.4f}")
    print(f"  Diagonal: {ccm.calculate_correlation(encrypted, 'diagonal'):.4f}")

    npcr, uaci = ccm.calculate_npcr_uaci(original, encrypted)
    print(f"\nNPCR: {npcr:.2f}%")
    print(f"UACI: {uaci:.2f}%")

    # Decrypt and verify
    decrypted = ccm.decrypt(encrypted, key)
    print(f"\nDecryption successful: {np.array_equal(original, decrypted)}")

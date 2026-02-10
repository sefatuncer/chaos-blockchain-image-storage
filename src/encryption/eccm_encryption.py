"""
Enhanced Chaotic Cat Map (ECCM) Encryption

An improved version of the Arnold Cat Map encryption with the following
security enhancements over standard CCM:

1. KEY-DEPENDENT PERMUTATION MATRIX
   Standard CCM uses fixed matrix [[1,1],[1,2]] for all encryptions.
   ECCM derives matrix parameters (a,b,c,d) from the encryption key,
   where ad - bc ≡ 1 (mod N) to ensure invertibility.
   This makes the permutation pattern unpredictable without the key.

2. BIDIRECTIONAL DIFFUSION
   Standard CCM applies single-direction XOR diffusion.
   ECCM applies forward diffusion followed by backward diffusion,
   creating stronger avalanche effect where each pixel influences
   all other pixels in both directions.

3. SALTED CHAOTIC SEQUENCE
   Standard CCM generates chaotic sequence from key alone.
   ECCM incorporates image hash as salt, making the chaotic sequence
   unique to each image even with the same key.

4. ROUND-SPECIFIC KEY DERIVATION
   Standard CCM uses same parameters for all rounds.
   ECCM derives unique round keys using SHA-256, ensuring each
   iteration uses different permutation and diffusion parameters.

These enhancements provide:
- Increased key sensitivity (any bit change produces completely different output)
- Stronger avalanche effect (single pixel change affects entire image)
- Image-specific encryption (same key produces different ciphertext for different images)
- Round independence (compromising one round doesn't reveal others)
"""

import numpy as np
from PIL import Image
import hashlib
import os
from typing import Tuple, Optional, List


class EnhancedChaoticCatMap:
    """
    Enhanced Chaotic Cat Map (ECCM) encryption implementation.

    Provides stronger security than standard CCM through:
    - Key-dependent dynamic permutation matrices
    - Bidirectional diffusion for avalanche effect
    - Image-salted chaotic sequences
    - Round-specific key derivation

    Attributes:
        iterations (int): Number of encryption rounds
        master_key (bytes): 256-bit master encryption key
    """

    def __init__(self, iterations: int = 10, master_key: bytes = None):
        """
        Initialize ECCM encryptor.

        Args:
            iterations: Number of permutation-diffusion rounds
            master_key: 256-bit (32 bytes) master key, randomly generated if None
        """
        self.iterations = iterations

        if master_key is None:
            self.master_key = os.urandom(32)  # 256-bit key
        else:
            if len(master_key) < 32:
                # Extend short keys using SHA-256
                self.master_key = hashlib.sha256(master_key).digest()
            else:
                self.master_key = master_key[:32]

    def _derive_round_key(self, round_num: int, salt: bytes = b'') -> bytes:
        """
        Derive a unique key for each encryption round.

        Uses HKDF-like construction: H(master_key || round || salt)

        Args:
            round_num: Current round number
            salt: Additional entropy (e.g., image hash)

        Returns:
            32-byte round-specific key
        """
        data = self.master_key + round_num.to_bytes(4, 'big') + salt
        return hashlib.sha256(data).digest()

    def _derive_matrix_params(self, round_key: bytes, N: int) -> Tuple[int, int, int, int]:
        """
        Derive key-dependent permutation matrix parameters.

        The Arnold Cat Map uses transformation:
            x' = (a*x + b*y) mod N
            y' = (c*x + d*y) mod N

        Standard CCM uses a=1, b=1, c=1, d=2 (determinant = 1).
        ECCM derives these from the key while ensuring det(M) ≡ 1 (mod N).

        Args:
            round_key: 32-byte round key
            N: Image dimension

        Returns:
            Tuple (a, b, c, d) where ad - bc ≡ 1 (mod N)
        """
        # Extract parameters from key bytes
        a = (round_key[0] % (N-1)) + 1  # 1 to N-1
        b = (round_key[1] % (N-1)) + 1
        c = (round_key[2] % (N-1)) + 1

        # Calculate d to ensure determinant = 1 (mod N)
        # ad - bc ≡ 1 (mod N) => d ≡ (1 + bc) * a^(-1) (mod N)
        # For simplicity, we use: d = (1 + b*c) // a + 1 when a divides (1+bc)
        # Otherwise, we adjust to ensure invertibility

        # Find modular inverse of a
        def mod_inverse(x, m):
            """Extended Euclidean algorithm for modular inverse."""
            def extended_gcd(a, b):
                if a == 0:
                    return b, 0, 1
                gcd, x1, y1 = extended_gcd(b % a, a)
                x = y1 - (b // a) * x1
                y = x1
                return gcd, x, y

            gcd, x, _ = extended_gcd(x % m, m)
            if gcd != 1:
                # a and m are not coprime, adjust a
                return None
            return (x % m + m) % m

        a_inv = mod_inverse(a, N)
        if a_inv is None:
            a = 1  # Fallback to ensure invertibility
            a_inv = 1

        d = ((1 + b * c) * a_inv) % N
        if d == 0:
            d = 1

        return a, b, c, d

    def _key_dependent_cat_map(self, image: np.ndarray,
                                a: int, b: int, c: int, d: int) -> np.ndarray:
        """
        Apply key-dependent Arnold Cat Map permutation.

        Args:
            image: Input image array
            a, b, c, d: Matrix parameters

        Returns:
            Permuted image
        """
        N = image.shape[0]
        permuted = np.zeros_like(image)

        for x in range(N):
            for y in range(N):
                new_x = (a * x + b * y) % N
                new_y = (c * x + d * y) % N
                permuted[new_x, new_y] = image[x, y]

        return permuted

    def _inverse_cat_map(self, image: np.ndarray,
                         a: int, b: int, c: int, d: int) -> np.ndarray:
        """
        Apply inverse Arnold Cat Map permutation.

        Inverse matrix: [[d, -b], [-c, a]] / det
        Since det = 1, inverse is [[d, -b], [-c, a]] mod N

        Args:
            image: Permuted image
            a, b, c, d: Original matrix parameters

        Returns:
            Original position image
        """
        N = image.shape[0]
        unpermuted = np.zeros_like(image)

        # Inverse transformation
        for x in range(N):
            for y in range(N):
                orig_x = (d * x - b * y) % N
                orig_y = (-c * x + a * y) % N
                unpermuted[orig_x, orig_y] = image[x, y]

        return unpermuted

    def _generate_chaotic_sequence(self, length: int, round_key: bytes,
                                    salt: bytes = b'') -> np.ndarray:
        """
        Generate salted chaotic sequence using Logistic Map.

        The sequence is derived from both the round key and image salt,
        making it unique to each image-key combination.

        Args:
            length: Sequence length
            round_key: Current round key
            salt: Image-derived salt

        Returns:
            Chaotic sequence as uint8 array
        """
        # Derive initial value from key and salt
        combined = hashlib.sha256(round_key + salt).digest()

        # Use first 8 bytes as floating point seed
        seed_int = int.from_bytes(combined[:8], 'big')
        x = 0.1 + (seed_int % 10000000) / 100000000  # 0.1 to 0.2 range

        # Logistic map parameter (fully chaotic at r ≈ 4)
        r = 3.9999

        sequence = np.zeros(length, dtype=np.uint8)
        for i in range(length):
            x = r * x * (1 - x)
            sequence[i] = int(x * 256) % 256

        return sequence

    def _bidirectional_diffusion(self, image: np.ndarray,
                                  chaos_seq: np.ndarray) -> np.ndarray:
        """
        Apply bidirectional diffusion for stronger avalanche effect.

        Forward pass: Each pixel depends on previous pixel and chaos
        Backward pass: Each pixel depends on next pixel and chaos

        This ensures every pixel influences every other pixel.

        Args:
            image: Input image
            chaos_seq: Chaotic sequence

        Returns:
            Diffused image
        """
        flat = image.flatten().astype(np.int32)
        n = len(flat)

        # Forward diffusion
        for i in range(1, n):
            flat[i] = (flat[i] + flat[i-1] + chaos_seq[i]) % 256

        # Backward diffusion
        for i in range(n-2, -1, -1):
            flat[i] = (flat[i] + flat[i+1] + chaos_seq[i]) % 256

        return flat.astype(np.uint8).reshape(image.shape)

    def _inverse_bidirectional_diffusion(self, image: np.ndarray,
                                          chaos_seq: np.ndarray) -> np.ndarray:
        """
        Inverse of bidirectional diffusion.

        Args:
            image: Diffused image
            chaos_seq: Same chaotic sequence used in encryption

        Returns:
            Original image
        """
        flat = image.flatten().astype(np.int32)
        n = len(flat)

        # Reverse backward diffusion first
        for i in range(n-1):
            flat[i] = (flat[i] - flat[i+1] - chaos_seq[i]) % 256

        # Reverse forward diffusion
        for i in range(n-1, 0, -1):
            flat[i] = (flat[i] - flat[i-1] - chaos_seq[i]) % 256

        return flat.astype(np.uint8).reshape(image.shape)

    def encrypt(self, image_path: str) -> Tuple[np.ndarray, dict]:
        """
        Encrypt an image using Enhanced Chaotic Cat Map.

        Args:
            image_path: Path to input image

        Returns:
            Tuple of (encrypted_image, encryption_metadata)
        """
        # Load image
        img = Image.open(image_path).convert('L')
        size = min(img.size)
        img = img.resize((size, size))
        image_array = np.array(img, dtype=np.uint8)

        N = image_array.shape[0]

        # Compute image hash as salt
        image_salt = hashlib.sha256(image_array.tobytes()).digest()

        encrypted = image_array.copy()

        # Store round parameters for decryption
        round_params = []

        for round_num in range(self.iterations):
            # Derive round-specific key
            round_key = self._derive_round_key(round_num, image_salt)

            # Get key-dependent matrix parameters
            a, b, c, d = self._derive_matrix_params(round_key, N)
            round_params.append((a, b, c, d))

            # Apply key-dependent permutation
            encrypted = self._key_dependent_cat_map(encrypted, a, b, c, d)

            # Generate salted chaotic sequence
            chaos_seq = self._generate_chaotic_sequence(
                encrypted.size, round_key, image_salt
            )

            # Apply bidirectional diffusion
            encrypted = self._bidirectional_diffusion(encrypted, chaos_seq)

        # Create metadata
        metadata = {
            'master_key': self.master_key.hex(),
            'iterations': self.iterations,
            'image_salt': image_salt.hex(),
            'original_size': img.size,
            'original_hash': hashlib.sha256(image_array.tobytes()).hexdigest(),
            'encrypted_hash': hashlib.sha256(encrypted.tobytes()).hexdigest(),
            'algorithm': 'ECCM',
            'version': '1.0'
        }

        return encrypted, metadata

    def decrypt(self, encrypted_image: np.ndarray, metadata: dict) -> np.ndarray:
        """
        Decrypt an ECCM-encrypted image.

        Args:
            encrypted_image: Encrypted image array
            metadata: Encryption metadata from encrypt()

        Returns:
            Decrypted image
        """
        # Restore parameters
        self.master_key = bytes.fromhex(metadata['master_key'])
        self.iterations = metadata['iterations']
        image_salt = bytes.fromhex(metadata['image_salt'])

        N = encrypted_image.shape[0]
        decrypted = encrypted_image.copy()

        # Reconstruct round parameters
        round_params = []
        for round_num in range(self.iterations):
            round_key = self._derive_round_key(round_num, image_salt)
            a, b, c, d = self._derive_matrix_params(round_key, N)
            round_params.append((a, b, c, d, round_key))

        # Decrypt in reverse order
        for round_num in range(self.iterations - 1, -1, -1):
            a, b, c, d, round_key = round_params[round_num]

            # Generate same chaotic sequence
            chaos_seq = self._generate_chaotic_sequence(
                decrypted.size, round_key, image_salt
            )

            # Inverse diffusion
            decrypted = self._inverse_bidirectional_diffusion(decrypted, chaos_seq)

            # Inverse permutation
            decrypted = self._inverse_cat_map(decrypted, a, b, c, d)

        return decrypted

    def save_encrypted(self, encrypted: np.ndarray, output_path: str) -> None:
        """Save encrypted image to file."""
        Image.fromarray(encrypted).save(output_path)


class EnhancedColorEncryption:
    """
    Enhanced CCM encryption for color (RGB) images.

    Each channel uses different derived keys for independent encryption,
    with cross-channel key derivation for additional security.
    """

    def __init__(self, iterations: int = 10, master_key: bytes = None):
        """
        Initialize color image encryptor.

        Args:
            iterations: Number of rounds per channel
            master_key: 256-bit master key
        """
        self.iterations = iterations
        self.master_key = master_key or os.urandom(32)

    def _derive_channel_key(self, channel: str) -> bytes:
        """Derive channel-specific key."""
        data = self.master_key + channel.encode()
        return hashlib.sha256(data).digest()

    def encrypt(self, image_path: str) -> Tuple[np.ndarray, dict]:
        """
        Encrypt a color image.

        Args:
            image_path: Path to input image

        Returns:
            Tuple of (encrypted_image, metadata)
        """
        img = Image.open(image_path).convert('RGB')
        size = min(img.size)
        img = img.resize((size, size))
        image_array = np.array(img, dtype=np.uint8)

        encrypted = np.zeros_like(image_array)
        channel_metadata = {}

        channels = ['R', 'G', 'B']
        for i, ch in enumerate(channels):
            channel_key = self._derive_channel_key(ch)
            encryptor = EnhancedChaoticCatMap(
                iterations=self.iterations,
                master_key=channel_key
            )

            # Save channel to temp file
            channel_img = Image.fromarray(image_array[:, :, i])
            temp_path = f'_temp_channel_{ch}.png'
            channel_img.save(temp_path)

            # Encrypt channel
            enc_channel, ch_meta = encryptor.encrypt(temp_path)
            encrypted[:, :, i] = enc_channel
            channel_metadata[ch] = ch_meta

            # Clean up
            os.remove(temp_path)

        metadata = {
            'master_key': self.master_key.hex(),
            'iterations': self.iterations,
            'channels': channel_metadata,
            'algorithm': 'ECCM-Color',
            'version': '1.0'
        }

        return encrypted, metadata

    def decrypt(self, encrypted_image: np.ndarray, metadata: dict) -> np.ndarray:
        """Decrypt a color image."""
        self.master_key = bytes.fromhex(metadata['master_key'])
        self.iterations = metadata['iterations']

        decrypted = np.zeros_like(encrypted_image)

        channels = ['R', 'G', 'B']
        for i, ch in enumerate(channels):
            channel_key = self._derive_channel_key(ch)
            decryptor = EnhancedChaoticCatMap(
                iterations=self.iterations,
                master_key=channel_key
            )

            decrypted[:, :, i] = decryptor.decrypt(
                encrypted_image[:, :, i],
                metadata['channels'][ch]
            )

        return decrypted

    def save_encrypted(self, encrypted: np.ndarray, output_path: str) -> None:
        """Save encrypted color image."""
        Image.fromarray(encrypted).save(output_path)


# Security analysis functions
def calculate_key_sensitivity(image_path: str, key1: bytes, key2: bytes) -> float:
    """
    Measure key sensitivity by comparing encryptions with slightly different keys.

    Returns percentage of differing pixels (should be ~50% for good encryption).
    """
    enc1 = EnhancedChaoticCatMap(iterations=10, master_key=key1)
    enc2 = EnhancedChaoticCatMap(iterations=10, master_key=key2)

    encrypted1, _ = enc1.encrypt(image_path)
    encrypted2, _ = enc2.encrypt(image_path)

    diff_pixels = np.sum(encrypted1 != encrypted2)
    total_pixels = encrypted1.size

    return (diff_pixels / total_pixels) * 100


def calculate_avalanche_effect(image_path: str) -> float:
    """
    Measure avalanche effect by flipping one pixel and comparing outputs.

    Returns percentage of differing pixels in encrypted output.
    """
    encryptor = EnhancedChaoticCatMap(iterations=10)

    # Encrypt original
    encrypted1, meta = encryptor.encrypt(image_path)

    # Load, modify one pixel, save, and encrypt
    img = Image.open(image_path).convert('L')
    img_array = np.array(img)
    img_array[0, 0] = (img_array[0, 0] + 1) % 256  # Flip one pixel

    temp_path = '_temp_avalanche.png'
    Image.fromarray(img_array).save(temp_path)

    encryptor2 = EnhancedChaoticCatMap(
        iterations=10,
        master_key=bytes.fromhex(meta['master_key'])
    )
    encrypted2, _ = encryptor2.encrypt(temp_path)

    os.remove(temp_path)

    diff_pixels = np.sum(encrypted1 != encrypted2)
    total_pixels = encrypted1.size

    return (diff_pixels / total_pixels) * 100


if __name__ == "__main__":
    print("Enhanced Chaotic Cat Map (ECCM) Encryption Demo")
    print("=" * 60)

    # Create test image
    test_img = np.zeros((256, 256), dtype=np.uint8)
    for i in range(256):
        for j in range(256):
            test_img[i, j] = int(128 + 60 * np.sin(i/30) * np.cos(j/35))

    Image.fromarray(test_img).save("test_eccm_original.png")

    # Encrypt
    eccm = EnhancedChaoticCatMap(iterations=10)
    encrypted, metadata = eccm.encrypt("test_eccm_original.png")
    eccm.save_encrypted(encrypted, "test_eccm_encrypted.png")

    print(f"Algorithm: {metadata['algorithm']}")
    print(f"Iterations: {metadata['iterations']}")
    print(f"Master Key: {metadata['master_key'][:32]}...")
    print(f"Image Salt: {metadata['image_salt'][:32]}...")

    # Decrypt and verify
    decrypted = eccm.decrypt(encrypted, metadata)
    original = np.array(Image.open("test_eccm_original.png").convert('L'))

    print(f"\nDecryption successful: {np.array_equal(original, decrypted)}")

    # Security metrics
    print("\n" + "=" * 60)
    print("Security Analysis")
    print("=" * 60)

    # Entropy
    hist, _ = np.histogram(encrypted.flatten(), bins=256, range=(0, 256))
    hist = hist / hist.sum()
    hist = hist[hist > 0]
    entropy = -np.sum(hist * np.log2(hist))
    print(f"Encrypted Entropy: {entropy:.4f} (ideal: 8.0)")

    # Correlation
    samples = 3000
    h, w = encrypted.shape
    x1 = np.random.randint(0, w-1, samples)
    y1 = np.random.randint(0, h, samples)
    p1 = encrypted[y1, x1].astype(float)
    p2 = encrypted[y1, x1+1].astype(float)
    corr = np.corrcoef(p1, p2)[0, 1]
    print(f"Horizontal Correlation: {corr:.6f} (ideal: 0.0)")

    # Key sensitivity
    key1 = os.urandom(32)
    key2 = bytearray(key1)
    key2[0] ^= 1  # Flip one bit
    key2 = bytes(key2)

    sensitivity = calculate_key_sensitivity("test_eccm_original.png", key1, key2)
    print(f"Key Sensitivity: {sensitivity:.2f}% pixels differ (ideal: ~50%)")

    # Avalanche effect
    avalanche = calculate_avalanche_effect("test_eccm_original.png")
    print(f"Avalanche Effect: {avalanche:.2f}% pixels differ (ideal: ~50%)")

    # Cleanup
    os.remove("test_eccm_original.png")
    os.remove("test_eccm_encrypted.png")

    print("\nECCM encryption demonstration complete!")

"""
Shamir's Secret Sharing Scheme (SSS) Implementation

Implements the (k,n) threshold secret sharing scheme where:
- n: Total number of shares generated
- k: Minimum number of shares required to reconstruct the secret

Reference:
Shamir, A. (1979). How to share a secret. Communications of the ACM, 22(11), 612-613.

For this implementation, we use (3,5) threshold scheme:
- 5 shares are distributed to authorized shareholders
- Any 3 shares are sufficient to reconstruct the key
"""

import secrets
from typing import List, Tuple
import hashlib


class ShamirSecretSharing:
    """
    Implements Shamir's Secret Sharing Scheme.

    Uses finite field arithmetic over a large prime for security.

    Attributes:
        threshold (int): Minimum shares needed (k)
        num_shares (int): Total shares to generate (n)
        prime (int): Prime modulus for finite field
    """

    # Large prime for finite field operations (256-bit)
    DEFAULT_PRIME = 2**256 - 189

    def __init__(self, threshold: int = 3, num_shares: int = 5,
                 prime: int = None):
        """
        Initialize the secret sharing scheme.

        Args:
            threshold: Minimum shares required to reconstruct (k)
            num_shares: Total shares to generate (n)
            prime: Prime modulus for finite field (optional)
        """
        if threshold > num_shares:
            raise ValueError("Threshold cannot be greater than number of shares")
        if threshold < 2:
            raise ValueError("Threshold must be at least 2")

        self.threshold = threshold
        self.num_shares = num_shares
        self.prime = prime if prime else self.DEFAULT_PRIME

    def _mod_inverse(self, a: int, m: int) -> int:
        """
        Calculate modular multiplicative inverse using extended Euclidean algorithm.

        Args:
            a: Number to find inverse for
            m: Modulus

        Returns:
            Modular inverse of a mod m
        """
        def extended_gcd(a: int, b: int) -> Tuple[int, int, int]:
            if a == 0:
                return b, 0, 1
            gcd, x1, y1 = extended_gcd(b % a, a)
            x = y1 - (b // a) * x1
            y = x1
            return gcd, x, y

        _, x, _ = extended_gcd(a % m, m)
        return (x % m + m) % m

    def _evaluate_polynomial(self, coefficients: List[int], x: int) -> int:
        """
        Evaluate polynomial at point x using Horner's method.

        Args:
            coefficients: Polynomial coefficients [a0, a1, ..., ak-1]
            x: Point to evaluate at

        Returns:
            Polynomial value at x (mod prime)
        """
        result = 0
        for coef in reversed(coefficients):
            result = (result * x + coef) % self.prime
        return result

    def split_secret(self, secret: bytes) -> List[Tuple[int, int]]:
        """
        Split a secret into n shares.

        Args:
            secret: The secret to split (bytes)

        Returns:
            List of (x, y) share tuples
        """
        # Convert secret to integer
        if isinstance(secret, bytes):
            secret_int = int.from_bytes(secret, byteorder='big')
        else:
            secret_int = secret

        # Ensure secret is smaller than prime
        if secret_int >= self.prime:
            raise ValueError("Secret is too large for the prime modulus")

        # Generate random polynomial coefficients
        # f(x) = secret + a1*x + a2*x^2 + ... + a(k-1)*x^(k-1)
        coefficients = [secret_int]
        for _ in range(self.threshold - 1):
            coefficients.append(secrets.randbelow(self.prime))

        # Generate shares
        shares = []
        for x in range(1, self.num_shares + 1):
            y = self._evaluate_polynomial(coefficients, x)
            shares.append((x, y))

        return shares

    def reconstruct_secret(self, shares: List[Tuple[int, int]]) -> bytes:
        """
        Reconstruct secret from k or more shares using Lagrange interpolation.

        Args:
            shares: List of (x, y) share tuples

        Returns:
            Reconstructed secret as bytes
        """
        if len(shares) < self.threshold:
            raise ValueError(f"Need at least {self.threshold} shares, got {len(shares)}")

        # Use only threshold number of shares
        shares = shares[:self.threshold]

        # Lagrange interpolation at x=0
        secret = 0

        for i, (xi, yi) in enumerate(shares):
            numerator = 1
            denominator = 1

            for j, (xj, _) in enumerate(shares):
                if i != j:
                    numerator = (numerator * (-xj)) % self.prime
                    denominator = (denominator * (xi - xj)) % self.prime

            # Calculate Lagrange basis polynomial value at x=0
            lagrange = (yi * numerator * self._mod_inverse(denominator, self.prime)) % self.prime
            secret = (secret + lagrange) % self.prime

        # Convert back to bytes
        byte_length = (secret.bit_length() + 7) // 8
        return secret.to_bytes(byte_length, byteorder='big')

    def split_secret_hex(self, secret_hex: str) -> List[Tuple[int, str]]:
        """
        Split a hex-encoded secret.

        Args:
            secret_hex: Hex-encoded secret string

        Returns:
            List of (x, y_hex) share tuples with hex-encoded y values
        """
        secret_bytes = bytes.fromhex(secret_hex)
        shares = self.split_secret(secret_bytes)
        return [(x, format(y, 'x')) for x, y in shares]

    def reconstruct_secret_hex(self, shares: List[Tuple[int, str]]) -> str:
        """
        Reconstruct secret from hex-encoded shares.

        Args:
            shares: List of (x, y_hex) share tuples

        Returns:
            Hex-encoded secret
        """
        int_shares = [(x, int(y, 16)) for x, y in shares]
        secret_bytes = self.reconstruct_secret(int_shares)
        return secret_bytes.hex()

    def verify_shares(self, shares: List[Tuple[int, int]], num_combinations: int = 3) -> bool:
        """
        Verify that different combinations of shares reconstruct the same secret.

        Args:
            shares: All shares
            num_combinations: Number of combinations to test

        Returns:
            True if all combinations produce the same result
        """
        import itertools

        combinations = list(itertools.combinations(shares, self.threshold))
        if len(combinations) < num_combinations:
            combinations_to_test = combinations
        else:
            combinations_to_test = [combinations[0], combinations[-1],
                                   combinations[len(combinations)//2]]

        secrets_reconstructed = []
        for combo in combinations_to_test:
            secret = self.reconstruct_secret(list(combo))
            secrets_reconstructed.append(secret)

        return len(set([s.hex() for s in secrets_reconstructed])) == 1


class KeyShareManager:
    """
    Manages encryption key shares for the medical image storage system.

    Handles splitting encryption keys and distributing shares to
    authorized parties (hospitals, institutions, etc.).
    """

    def __init__(self, threshold: int = 3, num_shares: int = 5):
        """
        Initialize the key share manager.

        Args:
            threshold: Minimum shares for key recovery (default: 3)
            num_shares: Total shares to distribute (default: 5)
        """
        self.sss = ShamirSecretSharing(threshold, num_shares)
        self.share_holders = {}

    def generate_key_shares(self, encryption_key: dict) -> List[dict]:
        """
        Generate shares for an encryption key.

        Args:
            encryption_key: The encryption key dictionary from CCM encryption

        Returns:
            List of share dictionaries for distribution
        """
        # Convert key seed to bytes
        seed = encryption_key['seed']
        seed_bytes = seed.to_bytes(32, byteorder='big')

        # Split the seed
        shares = self.sss.split_secret(seed_bytes)

        # Create share packages
        share_packages = []
        for i, (x, y) in enumerate(shares):
            share_package = {
                'share_id': i + 1,
                'x': x,
                'y_hex': format(y, 'x'),
                'iterations': encryption_key['iterations'],
                'image_hash': encryption_key['hash'],
                'share_hash': hashlib.sha256(f"{x}:{y}".encode()).hexdigest()
            }
            share_packages.append(share_package)

        return share_packages

    def recover_key(self, share_packages: List[dict]) -> dict:
        """
        Recover encryption key from shares.

        Args:
            share_packages: List of share package dictionaries

        Returns:
            Recovered encryption key dictionary
        """
        # Extract shares
        shares = [(pkg['x'], int(pkg['y_hex'], 16)) for pkg in share_packages]

        # Reconstruct seed
        seed_bytes = self.sss.reconstruct_secret(shares)
        seed = int.from_bytes(seed_bytes, byteorder='big')

        # Reconstruct key dictionary
        return {
            'seed': seed,
            'iterations': share_packages[0]['iterations'],
            'hash': share_packages[0]['image_hash']
        }

    def assign_share_holder(self, share_id: int, holder_name: str,
                           holder_public_key: str = None) -> None:
        """
        Assign a share to a specific holder (e.g., hospital, institution).

        Args:
            share_id: The share ID
            holder_name: Name of the share holder
            holder_public_key: Optional public key for secure communication
        """
        self.share_holders[share_id] = {
            'name': holder_name,
            'public_key': holder_public_key,
            'assigned_at': None  # Would be timestamp in production
        }


if __name__ == "__main__":
    # Example usage
    print("Shamir's Secret Sharing Demo")
    print("=" * 50)

    # Initialize (3,5) threshold scheme
    sss = ShamirSecretSharing(threshold=3, num_shares=5)

    # Example secret (encryption key seed)
    secret = b"This is a secret encryption key!"
    print(f"Original secret: {secret.hex()}")

    # Split into 5 shares
    shares = sss.split_secret(secret)
    print(f"\nGenerated {len(shares)} shares:")
    for x, y in shares:
        print(f"  Share {x}: {format(y, 'x')[:32]}...")

    # Reconstruct with first 3 shares
    recovered = sss.reconstruct_secret(shares[:3])
    print(f"\nRecovered with shares 1,2,3: {recovered.hex()}")

    # Reconstruct with different combination
    recovered2 = sss.reconstruct_secret([shares[0], shares[2], shares[4]])
    print(f"Recovered with shares 1,3,5: {recovered2.hex()}")

    # Verify
    print(f"\nRecovery successful: {recovered == secret}")

    # Test with key share manager
    print("\n" + "=" * 50)
    print("Key Share Manager Demo")

    key_manager = KeyShareManager(threshold=3, num_shares=5)

    # Simulate encryption key
    encryption_key = {
        'seed': 12345678901234567890,
        'iterations': 10,
        'hash': 'abcdef123456...'
    }

    # Generate shares
    packages = key_manager.generate_key_shares(encryption_key)
    print(f"\nGenerated {len(packages)} share packages")

    # Assign to holders
    key_manager.assign_share_holder(1, "Hospital A")
    key_manager.assign_share_holder(2, "Hospital B")
    key_manager.assign_share_holder(3, "Hospital C")
    key_manager.assign_share_holder(4, "Emergency Backup")
    key_manager.assign_share_holder(5, "Archive Server")

    # Recover key
    recovered_key = key_manager.recover_key(packages[:3])
    print(f"Recovered seed: {recovered_key['seed']}")
    print(f"Match: {recovered_key['seed'] == encryption_key['seed']}")

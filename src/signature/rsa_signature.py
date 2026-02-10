"""
RSA Digital Signature Implementation

Provides RSA-based digital signatures for image authentication and
integrity verification in the blockchain-based medical image storage system.

Uses SHA-256 for hashing and RSA-2048 for signing.

Provides RSA-2048 signatures with SHA-256 hashing for image
authentication in blockchain-based storage systems.
"""

import hashlib
from typing import Tuple, Optional
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature
import base64


class RSASignature:
    """
    Implements RSA digital signatures for image authentication.

    Uses RSA-2048 with SHA-256 for signing operations.

    Attributes:
        private_key: RSA private key for signing
        public_key: RSA public key for verification
        key_size: RSA key size in bits (default: 2048)
    """

    def __init__(self, key_size: int = 2048,
                 private_key_pem: bytes = None,
                 public_key_pem: bytes = None):
        """
        Initialize RSA signature system.

        Args:
            key_size: RSA key size in bits
            private_key_pem: Optional existing private key (PEM format)
            public_key_pem: Optional existing public key (PEM format)
        """
        self.key_size = key_size

        if private_key_pem:
            self.private_key = serialization.load_pem_private_key(
                private_key_pem, password=None, backend=default_backend()
            )
            self.public_key = self.private_key.public_key()
        elif public_key_pem:
            self.private_key = None
            self.public_key = serialization.load_pem_public_key(
                public_key_pem, backend=default_backend()
            )
        else:
            self._generate_key_pair()

    def _generate_key_pair(self) -> None:
        """Generate a new RSA key pair."""
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=self.key_size,
            backend=default_backend()
        )
        self.public_key = self.private_key.public_key()

    def get_private_key_pem(self) -> bytes:
        """
        Export private key in PEM format.

        Returns:
            Private key as PEM bytes
        """
        if not self.private_key:
            raise ValueError("No private key available")

        return self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )

    def get_public_key_pem(self) -> bytes:
        """
        Export public key in PEM format.

        Returns:
            Public key as PEM bytes
        """
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

    def hash_data(self, data: bytes) -> str:
        """
        Compute SHA-256 hash of data.

        Args:
            data: Data to hash

        Returns:
            Hex-encoded hash string
        """
        return hashlib.sha256(data).hexdigest()

    def hash_image(self, image_path: str) -> str:
        """
        Compute SHA-256 hash of an image file.

        Args:
            image_path: Path to image file

        Returns:
            Hex-encoded hash string
        """
        sha256_hash = hashlib.sha256()

        with open(image_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                sha256_hash.update(chunk)

        return sha256_hash.hexdigest()

    def sign(self, data: bytes) -> bytes:
        """
        Sign data using RSA private key.

        Args:
            data: Data to sign

        Returns:
            Signature bytes
        """
        if not self.private_key:
            raise ValueError("Private key required for signing")

        signature = self.private_key.sign(
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

        return signature

    def sign_hash(self, hash_hex: str) -> str:
        """
        Sign a hex-encoded hash.

        Args:
            hash_hex: Hex-encoded hash to sign

        Returns:
            Base64-encoded signature
        """
        hash_bytes = bytes.fromhex(hash_hex)
        signature = self.sign(hash_bytes)
        return base64.b64encode(signature).decode('utf-8')

    def sign_image(self, image_path: str) -> Tuple[str, str]:
        """
        Hash and sign an image file.

        Args:
            image_path: Path to image file

        Returns:
            Tuple of (hash, signature)
        """
        image_hash = self.hash_image(image_path)
        signature = self.sign_hash(image_hash)
        return image_hash, signature

    def verify(self, data: bytes, signature: bytes) -> bool:
        """
        Verify a signature.

        Args:
            data: Original data
            signature: Signature to verify

        Returns:
            True if signature is valid
        """
        try:
            self.public_key.verify(
                signature,
                data,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except InvalidSignature:
            return False

    def verify_hash(self, hash_hex: str, signature_b64: str) -> bool:
        """
        Verify a signature for a hex-encoded hash.

        Args:
            hash_hex: Hex-encoded hash
            signature_b64: Base64-encoded signature

        Returns:
            True if signature is valid
        """
        hash_bytes = bytes.fromhex(hash_hex)
        signature = base64.b64decode(signature_b64)
        return self.verify(hash_bytes, signature)

    def verify_image(self, image_path: str, expected_hash: str,
                    signature_b64: str) -> Tuple[bool, bool]:
        """
        Verify image integrity and authenticity.

        Args:
            image_path: Path to image file
            expected_hash: Expected hash value
            signature_b64: Base64-encoded signature

        Returns:
            Tuple of (hash_matches, signature_valid)
        """
        current_hash = self.hash_image(image_path)
        hash_matches = current_hash == expected_hash
        signature_valid = self.verify_hash(expected_hash, signature_b64)

        return hash_matches, signature_valid


class ImageAuthenticator:
    """
    High-level interface for image authentication in the medical imaging system.

    Combines hashing, signing, and verification operations.
    """

    def __init__(self, key_size: int = 2048):
        """
        Initialize the image authenticator.

        Args:
            key_size: RSA key size in bits
        """
        self.signer = RSASignature(key_size=key_size)

    def create_authentication_package(self, image_path: str,
                                      metadata: dict = None) -> dict:
        """
        Create a complete authentication package for an image.

        Args:
            image_path: Path to the image file
            metadata: Optional metadata to include

        Returns:
            Authentication package dictionary
        """
        # Hash the image
        image_hash = self.signer.hash_image(image_path)

        # Sign the hash
        signature = self.signer.sign_hash(image_hash)

        # Create package
        package = {
            'image_hash': image_hash,
            'signature': signature,
            'public_key': self.signer.get_public_key_pem().decode('utf-8'),
            'algorithm': 'RSA-2048-SHA256-PSS',
            'metadata': metadata or {}
        }

        return package

    def verify_authentication_package(self, image_path: str,
                                      package: dict) -> dict:
        """
        Verify an image against its authentication package.

        Args:
            image_path: Path to the image file
            package: Authentication package

        Returns:
            Verification result dictionary
        """
        # Load public key from package
        verifier = RSASignature(
            public_key_pem=package['public_key'].encode('utf-8')
        )

        # Verify
        hash_valid, sig_valid = verifier.verify_image(
            image_path,
            package['image_hash'],
            package['signature']
        )

        return {
            'hash_verified': hash_valid,
            'signature_verified': sig_valid,
            'overall_valid': hash_valid and sig_valid,
            'stored_hash': package['image_hash'],
            'computed_hash': verifier.hash_image(image_path)
        }


if __name__ == "__main__":
    # Example usage
    print("RSA Digital Signature Demo")
    print("=" * 50)

    # Initialize signer
    signer = RSASignature()

    # Example data
    data = b"Medical image hash: abc123def456..."
    print(f"Data: {data.decode()}")

    # Sign
    signature = signer.sign(data)
    print(f"Signature: {base64.b64encode(signature).decode()[:64]}...")

    # Verify
    is_valid = signer.verify(data, signature)
    print(f"Signature valid: {is_valid}")

    # Tampered data
    tampered = b"Medical image hash: TAMPERED..."
    is_valid_tampered = signer.verify(tampered, signature)
    print(f"Tampered data valid: {is_valid_tampered}")

    # Hash signing example
    print("\n" + "=" * 50)
    print("Hash Signing Demo")

    image_hash = hashlib.sha256(b"test image data").hexdigest()
    print(f"Image hash: {image_hash}")

    sig_b64 = signer.sign_hash(image_hash)
    print(f"Signature (base64): {sig_b64[:64]}...")

    # Verify hash
    is_hash_valid = signer.verify_hash(image_hash, sig_b64)
    print(f"Hash signature valid: {is_hash_valid}")

    # Export keys
    print("\n" + "=" * 50)
    print("Key Export Demo")

    public_pem = signer.get_public_key_pem()
    print(f"Public key (first line): {public_pem.decode().split(chr(10))[0]}")

    private_pem = signer.get_private_key_pem()
    print(f"Private key (first line): {private_pem.decode().split(chr(10))[0]}")

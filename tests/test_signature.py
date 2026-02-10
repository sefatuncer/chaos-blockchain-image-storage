"""
Unit Tests for RSA Digital Signature

Tests the RSA signature implementation for image authentication.
"""

import pytest
import tempfile
import os
import sys
import numpy as np
from PIL import Image

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from src.signature import RSASignature


class TestRSASignature:
    """Tests for RSA digital signature implementation."""

    def test_sign_verify(self):
        """Test basic signing and verification."""
        signer = RSASignature()
        data = b"Test message for signing"

        signature = signer.sign(data)
        assert signer.verify(data, signature)

    def test_tampered_data(self):
        """Test that tampered data fails verification."""
        signer = RSASignature()
        data = b"Original message"

        signature = signer.sign(data)

        tampered = b"Tampered message"
        assert not signer.verify(tampered, signature)

    def test_hash_signing(self):
        """Test hex hash signing and verification."""
        signer = RSASignature()
        hash_hex = "abc123def456789012345678901234567890123456789012345678901234"

        signature = signer.sign_hash(hash_hex)
        assert signer.verify_hash(hash_hex, signature)

    def test_key_export_import(self):
        """Test key export and import."""
        # Generate key pair
        signer1 = RSASignature()
        public_pem = signer1.get_public_key_pem()
        private_pem = signer1.get_private_key_pem()

        # Sign with original
        data = b"Test data"
        signature = signer1.sign(data)

        # Verify with imported public key only
        signer2 = RSASignature(public_key_pem=public_pem)
        assert signer2.verify(data, signature)

        # Verify with imported private key (which includes public)
        signer3 = RSASignature(private_key_pem=private_pem)
        assert signer3.verify(data, signature)

    def test_image_hashing(self):
        """Test image file hashing."""
        # Create temp image
        img = np.random.randint(0, 256, (64, 64), dtype=np.uint8)
        with tempfile.NamedTemporaryFile(suffix='.png', delete=False) as f:
            Image.fromarray(img).save(f.name)
            temp_path = f.name

        try:
            signer = RSASignature()
            hash1 = signer.hash_image(temp_path)
            hash2 = signer.hash_image(temp_path)

            # Same image should produce same hash
            assert hash1 == hash2
            assert len(hash1) == 64  # SHA-256 hex length

        finally:
            os.unlink(temp_path)

    def test_image_signing(self):
        """Test complete image signing workflow."""
        # Create temp image
        img = np.random.randint(0, 256, (64, 64), dtype=np.uint8)
        with tempfile.NamedTemporaryFile(suffix='.png', delete=False) as f:
            Image.fromarray(img).save(f.name)
            temp_path = f.name

        try:
            signer = RSASignature()
            image_hash, signature = signer.sign_image(temp_path)

            # Verify
            hash_valid, sig_valid = signer.verify_image(
                temp_path, image_hash, signature
            )

            assert hash_valid
            assert sig_valid

        finally:
            os.unlink(temp_path)

    def test_modified_image_detection(self):
        """Test that modified images fail verification."""
        # Create original image
        img1 = np.zeros((64, 64), dtype=np.uint8)
        with tempfile.NamedTemporaryFile(suffix='.png', delete=False) as f:
            Image.fromarray(img1).save(f.name)
            path1 = f.name

        # Create modified image
        img2 = np.ones((64, 64), dtype=np.uint8) * 255
        with tempfile.NamedTemporaryFile(suffix='.png', delete=False) as f:
            Image.fromarray(img2).save(f.name)
            path2 = f.name

        try:
            signer = RSASignature()

            # Sign original
            orig_hash, signature = signer.sign_image(path1)

            # Verify modified
            hash_valid, sig_valid = signer.verify_image(
                path2, orig_hash, signature
            )

            assert not hash_valid  # Hash should not match

        finally:
            os.unlink(path1)
            os.unlink(path2)

    def test_different_key_sizes(self):
        """Test with different RSA key sizes."""
        for key_size in [1024, 2048, 4096]:
            signer = RSASignature(key_size=key_size)
            data = b"Test message"

            signature = signer.sign(data)
            assert signer.verify(data, signature)


class TestImageAuthenticator:
    """Tests for the ImageAuthenticator class."""

    def test_authentication_package(self):
        """Test complete authentication package creation."""
        from src.signature.rsa_signature import ImageAuthenticator

        # Create temp image
        img = np.random.randint(0, 256, (64, 64), dtype=np.uint8)
        with tempfile.NamedTemporaryFile(suffix='.png', delete=False) as f:
            Image.fromarray(img).save(f.name)
            temp_path = f.name

        try:
            auth = ImageAuthenticator()
            package = auth.create_authentication_package(
                temp_path,
                metadata={'patient_id': 'P12345'}
            )

            assert 'image_hash' in package
            assert 'signature' in package
            assert 'public_key' in package
            assert 'algorithm' in package
            assert package['metadata']['patient_id'] == 'P12345'

        finally:
            os.unlink(temp_path)

    def test_package_verification(self):
        """Test authentication package verification."""
        from src.signature.rsa_signature import ImageAuthenticator

        # Create temp image
        img = np.random.randint(0, 256, (64, 64), dtype=np.uint8)
        with tempfile.NamedTemporaryFile(suffix='.png', delete=False) as f:
            Image.fromarray(img).save(f.name)
            temp_path = f.name

        try:
            auth = ImageAuthenticator()
            package = auth.create_authentication_package(temp_path)

            result = auth.verify_authentication_package(temp_path, package)

            assert result['hash_verified']
            assert result['signature_verified']
            assert result['overall_valid']

        finally:
            os.unlink(temp_path)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

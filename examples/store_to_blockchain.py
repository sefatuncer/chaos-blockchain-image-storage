#!/usr/bin/env python3
"""
Example: Store Encrypted Image Metadata on Blockchain

This script demonstrates the complete workflow of:
1. Encrypting an image using CCM
2. Splitting the encryption key using Shamir's Secret Sharing
3. Signing the image hash with RSA
4. Storing metadata on the Hyperledger Fabric blockchain

Usage:
    python store_to_blockchain.py <image_path> <image_id>
"""

import sys
import os
import json

# Add parent directory to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from src.encryption import ChaoticCatMapEncryption
from src.secret_sharing import ShamirSecretSharing
from src.signature import RSASignature
from src.blockchain import FabricClient


def main():
    if len(sys.argv) < 3:
        print("Usage: python store_to_blockchain.py <image_path> <image_id>")
        sys.exit(1)

    image_path = sys.argv[1]
    image_id = sys.argv[2]

    if not os.path.exists(image_path):
        print(f"Error: Image file not found: {image_path}")
        sys.exit(1)

    print("=" * 60)
    print("Medical Image Blockchain Storage Workflow")
    print("=" * 60)

    # Step 1: Encrypt the image
    print("\n[Step 1] Encrypting image with Chaotic Cat Map...")
    ccm = ChaoticCatMapEncryption(iterations=10)
    encrypted, encryption_key = ccm.encrypt(image_path)

    encrypted_path = f"{image_id}_encrypted.png"
    ccm.save_encrypted(encrypted, encrypted_path)
    print(f"  - Encrypted image saved: {encrypted_path}")
    print(f"  - Seed: {encryption_key['seed']}")
    print(f"  - Iterations: {encryption_key['iterations']}")

    # Step 2: Split encryption key using Shamir's Secret Sharing
    print("\n[Step 2] Splitting encryption key with (7,10) threshold...")
    sss = ShamirSecretSharing(threshold=7, num_shares=10)

    # Convert seed to bytes for sharing
    seed_bytes = encryption_key['seed'].to_bytes(32, byteorder='big')
    shares = sss.split_secret(seed_bytes)

    share_info = []
    for i, (x, y) in enumerate(shares):
        share_info.append({
            'share_id': i + 1,
            'x': x,
            'y_hex': format(y, 'x')[:32] + '...',  # Truncated for display
            'share_hash': format(hash(y), 'x')
        })
        print(f"  - Share {i+1}: x={x}")

    # Step 3: Sign the image hash
    print("\n[Step 3] Signing encrypted image with RSA...")
    signer = RSASignature(key_size=2048)
    image_hash, signature = signer.sign_image(encrypted_path)

    print(f"  - Image hash: {image_hash[:32]}...")
    print(f"  - Signature: {signature[:32]}...")

    # Step 4: Store on blockchain
    print("\n[Step 4] Storing metadata on Hyperledger Fabric blockchain...")

    fabric_client = FabricClient(
        channel_name="medical-images",
        chaincode_name="imagestore"
    )
    fabric_client.connect()

    tx_id = fabric_client.store_image_metadata(
        image_id=image_id,
        hash_value=image_hash,
        signature=signature,
        encrypted_shares=share_info,
        metadata={
            'iterations': encryption_key['iterations'],
            'encryption_method': 'CCM',
            'threshold': '7/10',
            'original_hash': encryption_key['hash']
        }
    )

    print(f"  - Transaction ID: {tx_id}")

    # Summary
    print("\n" + "=" * 60)
    print("Storage Complete!")
    print("=" * 60)
    print(f"Image ID: {image_id}")
    print(f"Encrypted file: {encrypted_path}")
    print(f"Blockchain TX: {tx_id}")
    print(f"Key shares distributed: 5 (minimum 3 required for recovery)")

    # Save complete record
    record = {
        'image_id': image_id,
        'encrypted_path': encrypted_path,
        'image_hash': image_hash,
        'signature': signature,
        'tx_id': tx_id,
        'shares': share_info,
        'encryption': {
            'method': 'CCM',
            'iterations': encryption_key['iterations']
        }
    }

    record_path = f"{image_id}_record.json"
    with open(record_path, 'w') as f:
        json.dump(record, f, indent=2)

    print(f"\nComplete record saved: {record_path}")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
Example: Verify Image Integrity using Blockchain

This script demonstrates how to verify the integrity and authenticity
of an encrypted medical image using the blockchain record.

Usage:
    python verify_image.py <image_id> <encrypted_image_path>
"""

import sys
import os
import json
import hashlib

# Add parent directory to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from src.signature import RSASignature
from src.blockchain import FabricClient


def calculate_image_hash(image_path: str) -> str:
    """Calculate SHA-256 hash of an image file."""
    sha256_hash = hashlib.sha256()

    with open(image_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            sha256_hash.update(chunk)

    return sha256_hash.hexdigest()


def main():
    if len(sys.argv) < 3:
        print("Usage: python verify_image.py <image_id> <encrypted_image_path>")
        sys.exit(1)

    image_id = sys.argv[1]
    image_path = sys.argv[2]

    if not os.path.exists(image_path):
        print(f"Error: Image file not found: {image_path}")
        sys.exit(1)

    print("=" * 60)
    print("Medical Image Verification")
    print("=" * 60)

    # Step 1: Calculate current image hash
    print("\n[Step 1] Calculating current image hash...")
    current_hash = calculate_image_hash(image_path)
    print(f"  - Current hash: {current_hash[:32]}...")

    # Step 2: Retrieve blockchain record
    print("\n[Step 2] Retrieving blockchain record...")

    fabric_client = FabricClient(
        channel_name="medical-images",
        chaincode_name="imagestore"
    )
    fabric_client.connect()

    # First, let's check if we have a local record (for demo purposes)
    record_path = f"{image_id}_record.json"
    if os.path.exists(record_path):
        with open(record_path, 'r') as f:
            stored_record = json.load(f)
        print(f"  - Found stored record: {record_path}")
        stored_hash = stored_record['image_hash']
        stored_signature = stored_record['signature']
    else:
        # Query blockchain
        result = fabric_client.verify_image(image_id, current_hash)
        if result.get('error'):
            print(f"  - Error: {result['error']}")
            sys.exit(1)
        stored_hash = result.get('stored_hash', '')
        stored_signature = None

    print(f"  - Stored hash: {stored_hash[:32]}...")

    # Step 3: Compare hashes
    print("\n[Step 3] Comparing hashes...")
    hash_matches = current_hash == stored_hash

    if hash_matches:
        print("  - HASH VERIFIED: Image has not been modified")
    else:
        print("  - HASH MISMATCH: Image may have been tampered with!")
        print(f"    Expected: {stored_hash[:32]}...")
        print(f"    Got:      {current_hash[:32]}...")

    # Step 4: Verify signature (if available)
    if stored_signature:
        print("\n[Step 4] Verifying digital signature...")
        # Note: In production, we would need the public key from blockchain
        # For demo, we'll check if signature was stored
        print(f"  - Signature present: {stored_signature[:32]}...")
        print("  - Signature verification requires original public key")

    # Step 5: Get transaction history
    print("\n[Step 5] Checking transaction history...")
    history = fabric_client.get_image_history(image_id)
    print(f"  - Found {len(history)} transaction(s)")

    for i, tx in enumerate(history):
        print(f"    [{i+1}] TX: {tx.get('tx_id', 'N/A')}")
        print(f"        Time: {tx.get('created_at', 'N/A')}")

    # Summary
    print("\n" + "=" * 60)
    print("Verification Summary")
    print("=" * 60)
    print(f"Image ID: {image_id}")
    print(f"Hash Match: {'YES' if hash_matches else 'NO'}")
    print(f"Integrity: {'VERIFIED' if hash_matches else 'COMPROMISED'}")

    if hash_matches:
        print("\nThe image has not been modified since it was stored.")
    else:
        print("\nWARNING: The image appears to have been modified!")
        print("Please investigate the source of this discrepancy.")

    return hash_matches


if __name__ == "__main__":
    result = main()
    sys.exit(0 if result else 1)

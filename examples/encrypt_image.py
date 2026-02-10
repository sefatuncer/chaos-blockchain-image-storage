#!/usr/bin/env python3
"""
Example: Encrypt a Medical Image using Chaotic Cat Map

This script demonstrates how to encrypt a medical image using the
CCM encryption implementation provided in this supplementary material.

Usage:
    python encrypt_image.py <input_image> <output_image>
    python encrypt_image.py --color <input_image> <output_image>
"""

import sys
import os

# Add parent directory to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from src.encryption import ChaoticCatMapEncryption, ColorImageEncryption
import json


def encrypt_grayscale(input_path: str, output_path: str):
    """Encrypt a grayscale image."""
    print(f"Encrypting grayscale image: {input_path}")

    # Initialize encryptor
    ccm = ChaoticCatMapEncryption(iterations=10)

    # Encrypt
    encrypted, key = ccm.encrypt(input_path)

    # Save encrypted image
    ccm.save_encrypted(encrypted, output_path)

    # Save key to JSON file
    key_path = output_path.rsplit('.', 1)[0] + '_key.json'
    with open(key_path, 'w') as f:
        json.dump(key, f, indent=2)

    print(f"Encrypted image saved: {output_path}")
    print(f"Encryption key saved: {key_path}")

    # Calculate and display metrics
    print("\nEncryption Metrics:")
    print(f"  Entropy: {ccm.calculate_entropy(encrypted):.4f}")
    print(f"  Horizontal Correlation: {ccm.calculate_correlation(encrypted, 'horizontal'):.4f}")
    print(f"  Vertical Correlation: {ccm.calculate_correlation(encrypted, 'vertical'):.4f}")
    print(f"  Diagonal Correlation: {ccm.calculate_correlation(encrypted, 'diagonal'):.4f}")

    return key


def encrypt_color(input_path: str, output_path: str):
    """Encrypt a color image."""
    print(f"Encrypting color image: {input_path}")

    # Initialize encryptor
    ccm = ColorImageEncryption(iterations=10)

    # Encrypt
    encrypted, key = ccm.encrypt(input_path)

    # Save encrypted image
    ccm.save_encrypted(encrypted, output_path)

    # Save key to JSON file
    key_path = output_path.rsplit('.', 1)[0] + '_key.json'
    with open(key_path, 'w') as f:
        json.dump(key, f, indent=2)

    print(f"Encrypted image saved: {output_path}")
    print(f"Encryption key saved: {key_path}")

    # Calculate and display metrics
    r_ent, g_ent, b_ent, avg_ent = ccm.calculate_entropy(encrypted)
    print("\nEncryption Metrics:")
    print(f"  Entropy (R/G/B/Avg): {r_ent:.4f} / {g_ent:.4f} / {b_ent:.4f} / {avg_ent:.4f}")

    r_corr, g_corr, b_corr, avg_corr = ccm.calculate_correlation(encrypted, 'horizontal')
    print(f"  Horizontal Correlation: {avg_corr:.4f}")

    return key


def main():
    if len(sys.argv) < 3:
        print("Usage: python encrypt_image.py [--color] <input_image> <output_image>")
        sys.exit(1)

    color_mode = False
    args = sys.argv[1:]

    if args[0] == '--color':
        color_mode = True
        args = args[1:]

    if len(args) < 2:
        print("Error: Missing input or output path")
        sys.exit(1)

    input_path = args[0]
    output_path = args[1]

    if not os.path.exists(input_path):
        print(f"Error: Input file not found: {input_path}")
        sys.exit(1)

    if color_mode:
        encrypt_color(input_path, output_path)
    else:
        encrypt_grayscale(input_path, output_path)

    print("\nEncryption completed successfully!")


if __name__ == "__main__":
    main()

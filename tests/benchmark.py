#!/usr/bin/env python3
"""
Benchmark Suite for Medical Image Security System

This script runs comprehensive benchmarks for all system components:
- CCM encryption performance
- Secret sharing performance
- RSA signature performance
- Blockchain operation latency (simulated)

Usage:
    python benchmark.py [--quick] [--output results.json]
"""

import sys
import os
import time
import json
import argparse
import numpy as np
from PIL import Image
import tempfile
from typing import Dict, List, Tuple
from datetime import datetime

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from src.encryption import ChaoticCatMapEncryption, ColorImageEncryption
from src.secret_sharing import ShamirSecretSharing
from src.signature import RSASignature


class BenchmarkSuite:
    """Comprehensive benchmark suite for the security system."""

    def __init__(self, quick_mode: bool = False):
        """
        Initialize benchmark suite.

        Args:
            quick_mode: If True, run abbreviated benchmarks
        """
        self.quick_mode = quick_mode
        self.results = {
            'timestamp': datetime.now().isoformat(),
            'mode': 'quick' if quick_mode else 'full',
            'encryption': {},
            'secret_sharing': {},
            'signature': {},
            'summary': {}
        }

    def create_test_image(self, size: int, color: bool = False) -> str:
        """Create a test image of specified size."""
        if color:
            img = np.random.randint(0, 256, (size, size, 3), dtype=np.uint8)
        else:
            img = np.random.randint(0, 256, (size, size), dtype=np.uint8)

        with tempfile.NamedTemporaryFile(suffix='.png', delete=False) as f:
            Image.fromarray(img).save(f.name)
            return f.name

    def benchmark_encryption(self) -> Dict:
        """Benchmark CCM encryption performance."""
        print("\n" + "=" * 60)
        print("Encryption Benchmarks")
        print("=" * 60)

        sizes = [256, 512] if self.quick_mode else [256, 512, 1024, 2048]
        iterations_list = [5, 10] if self.quick_mode else [5, 10, 15, 20]
        num_runs = 3 if self.quick_mode else 5

        results = {
            'grayscale': [],
            'color': [],
            'metrics': []
        }

        # Grayscale benchmarks
        print("\nGrayscale Encryption:")
        for size in sizes:
            img_path = self.create_test_image(size, color=False)
            try:
                times = []
                for _ in range(num_runs):
                    ccm = ChaoticCatMapEncryption(iterations=10)
                    start = time.perf_counter()
                    encrypted, key = ccm.encrypt(img_path)
                    elapsed = (time.perf_counter() - start) * 1000

                    times.append(elapsed)

                avg_time = np.mean(times)
                std_time = np.std(times)

                results['grayscale'].append({
                    'size': f"{size}x{size}",
                    'pixels': size * size,
                    'avg_time_ms': round(avg_time, 2),
                    'std_time_ms': round(std_time, 2),
                    'throughput_mpps': round((size * size) / (avg_time * 1000), 4)
                })

                print(f"  {size}x{size}: {avg_time:.2f}ms (±{std_time:.2f})")

                # Calculate metrics for largest size
                if size == sizes[-1]:
                    entropy = ccm.calculate_entropy(encrypted)
                    corr_h = ccm.calculate_correlation(encrypted, 'horizontal')
                    corr_v = ccm.calculate_correlation(encrypted, 'vertical')
                    corr_d = ccm.calculate_correlation(encrypted, 'diagonal')

                    original = np.array(Image.open(img_path).convert('L'))
                    original = original[:encrypted.shape[0], :encrypted.shape[1]]
                    npcr, uaci = ccm.calculate_npcr_uaci(original, encrypted)

                    results['metrics'].append({
                        'type': 'grayscale',
                        'size': f"{size}x{size}",
                        'entropy': round(entropy, 4),
                        'npcr': round(npcr, 2),
                        'uaci': round(uaci, 2),
                        'correlation_h': round(abs(corr_h), 4),
                        'correlation_v': round(abs(corr_v), 4),
                        'correlation_d': round(abs(corr_d), 4)
                    })

            finally:
                os.unlink(img_path)

        # Color benchmarks
        print("\nColor Encryption:")
        for size in sizes[:2]:  # Color is slower, test fewer sizes
            img_path = self.create_test_image(size, color=True)
            try:
                times = []
                for _ in range(num_runs):
                    ccm = ColorImageEncryption(iterations=10)
                    start = time.perf_counter()
                    encrypted, key = ccm.encrypt(img_path)
                    elapsed = (time.perf_counter() - start) * 1000

                    times.append(elapsed)

                avg_time = np.mean(times)
                std_time = np.std(times)

                results['color'].append({
                    'size': f"{size}x{size}",
                    'pixels': size * size * 3,
                    'avg_time_ms': round(avg_time, 2),
                    'std_time_ms': round(std_time, 2)
                })

                print(f"  {size}x{size} RGB: {avg_time:.2f}ms (±{std_time:.2f})")

            finally:
                os.unlink(img_path)

        # Iterations benchmark
        print("\nIteration Impact:")
        img_path = self.create_test_image(512, color=False)
        try:
            iteration_results = []
            for iters in iterations_list:
                ccm = ChaoticCatMapEncryption(iterations=iters)
                start = time.perf_counter()
                encrypted, _ = ccm.encrypt(img_path)
                elapsed = (time.perf_counter() - start) * 1000

                iteration_results.append({
                    'iterations': iters,
                    'time_ms': round(elapsed, 2)
                })

                print(f"  {iters} iterations: {elapsed:.2f}ms")

            results['iterations'] = iteration_results

        finally:
            os.unlink(img_path)

        return results

    def benchmark_secret_sharing(self) -> Dict:
        """Benchmark Shamir's Secret Sharing performance."""
        print("\n" + "=" * 60)
        print("Secret Sharing Benchmarks")
        print("=" * 60)

        configs = [(2, 3), (3, 5), (4, 7), (5, 9)]
        key_sizes = [128, 256] if self.quick_mode else [128, 256, 512]
        num_runs = 10 if self.quick_mode else 50

        results = []

        for t, n in configs:
            print(f"\n({t},{n}) Threshold:")

            for key_size in key_sizes:
                secret = os.urandom(key_size // 8)

                split_times = []
                reconstruct_times = []

                for _ in range(num_runs):
                    sss = ShamirSecretSharing(threshold=t, num_shares=n)

                    # Split
                    start = time.perf_counter()
                    shares = sss.split_secret(secret)
                    split_times.append((time.perf_counter() - start) * 1000)

                    # Reconstruct
                    start = time.perf_counter()
                    recovered = sss.reconstruct_secret(shares[:t])
                    reconstruct_times.append((time.perf_counter() - start) * 1000)

                avg_split = np.mean(split_times)
                avg_reconstruct = np.mean(reconstruct_times)

                results.append({
                    'config': f"({t},{n})",
                    'key_size_bits': key_size,
                    'split_time_ms': round(avg_split, 3),
                    'reconstruct_time_ms': round(avg_reconstruct, 3)
                })

                print(f"  {key_size}-bit: split={avg_split:.3f}ms, reconstruct={avg_reconstruct:.3f}ms")

        return results

    def benchmark_signature(self) -> Dict:
        """Benchmark RSA signature performance."""
        print("\n" + "=" * 60)
        print("RSA Signature Benchmarks")
        print("=" * 60)

        key_sizes = [2048] if self.quick_mode else [1024, 2048, 4096]
        data_sizes = [32, 64] if self.quick_mode else [32, 64, 128, 256]
        num_runs = 10 if self.quick_mode else 50

        results = []

        for key_size in key_sizes:
            print(f"\nRSA-{key_size}:")

            # Key generation
            start = time.perf_counter()
            signer = RSASignature(key_size=key_size)
            keygen_time = (time.perf_counter() - start) * 1000

            for data_size in data_sizes:
                data = os.urandom(data_size)

                sign_times = []
                verify_times = []

                for _ in range(num_runs):
                    # Sign
                    start = time.perf_counter()
                    signature = signer.sign(data)
                    sign_times.append((time.perf_counter() - start) * 1000)

                    # Verify
                    start = time.perf_counter()
                    valid = signer.verify(data, signature)
                    verify_times.append((time.perf_counter() - start) * 1000)

                avg_sign = np.mean(sign_times)
                avg_verify = np.mean(verify_times)

                results.append({
                    'key_size': key_size,
                    'data_size_bytes': data_size,
                    'keygen_time_ms': round(keygen_time, 2),
                    'sign_time_ms': round(avg_sign, 3),
                    'verify_time_ms': round(avg_verify, 3)
                })

                print(f"  {data_size} bytes: sign={avg_sign:.3f}ms, verify={avg_verify:.3f}ms")

        return results

    def run_all(self) -> Dict:
        """Run all benchmarks."""
        print("=" * 60)
        print("Medical Image Security System - Benchmark Suite")
        print("=" * 60)
        print(f"Mode: {'Quick' if self.quick_mode else 'Full'}")
        print(f"Started: {self.results['timestamp']}")

        # Run benchmarks
        self.results['encryption'] = self.benchmark_encryption()
        self.results['secret_sharing'] = self.benchmark_secret_sharing()
        self.results['signature'] = self.benchmark_signature()

        # Summary
        print("\n" + "=" * 60)
        print("Summary")
        print("=" * 60)

        if self.results['encryption']['grayscale']:
            enc_512 = next(
                (r for r in self.results['encryption']['grayscale']
                 if r['size'] == '512x512'),
                None
            )
            if enc_512:
                print(f"Encryption (512x512): {enc_512['avg_time_ms']:.2f}ms")

        if self.results['secret_sharing']:
            sss_35 = next(
                (r for r in self.results['secret_sharing']
                 if r['config'] == '(3,5)' and r['key_size_bits'] == 256),
                None
            )
            if sss_35:
                print(f"Secret Sharing (3,5): split={sss_35['split_time_ms']:.3f}ms, "
                      f"reconstruct={sss_35['reconstruct_time_ms']:.3f}ms")

        if self.results['signature']:
            rsa_2048 = next(
                (r for r in self.results['signature']
                 if r['key_size'] == 2048 and r['data_size_bytes'] == 64),
                None
            )
            if rsa_2048:
                print(f"RSA-2048 Signature: sign={rsa_2048['sign_time_ms']:.3f}ms, "
                      f"verify={rsa_2048['verify_time_ms']:.3f}ms")

        if self.results['encryption']['metrics']:
            metrics = self.results['encryption']['metrics'][0]
            print(f"\nEncryption Quality:")
            print(f"  Entropy: {metrics['entropy']}")
            print(f"  NPCR: {metrics['npcr']}%")
            print(f"  UACI: {metrics['uaci']}%")
            print(f"  Correlation (H/V/D): {metrics['correlation_h']}/{metrics['correlation_v']}/{metrics['correlation_d']}")

        self.results['summary'] = {
            'total_benchmarks': (
                len(self.results['encryption'].get('grayscale', [])) +
                len(self.results['encryption'].get('color', [])) +
                len(self.results['secret_sharing']) +
                len(self.results['signature'])
            ),
            'completed': datetime.now().isoformat()
        }

        return self.results

    def save_results(self, output_path: str) -> None:
        """Save results to JSON file."""
        with open(output_path, 'w') as f:
            json.dump(self.results, f, indent=2)
        print(f"\nResults saved to: {output_path}")


def main():
    parser = argparse.ArgumentParser(description='Run security system benchmarks')
    parser.add_argument('--quick', action='store_true', help='Run quick benchmarks')
    parser.add_argument('--output', type=str, default='benchmark_results.json',
                       help='Output file path')

    args = parser.parse_args()

    suite = BenchmarkSuite(quick_mode=args.quick)
    results = suite.run_all()
    suite.save_results(args.output)

    print("\nBenchmark completed!")


if __name__ == "__main__":
    main()

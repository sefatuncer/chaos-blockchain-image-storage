"""
Shamir's Secret Sharing Module

Implements (k,n) threshold secret sharing scheme for secure key distribution.
"""

from .shamir import ShamirSecretSharing

__all__ = ['ShamirSecretSharing']

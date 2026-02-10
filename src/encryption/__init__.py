"""
Chaotic Cat Map (CCM) Image Encryption Module

This module implements chaos-based image encryption using the Arnold Cat Map
transformation for secure medical image storage.

Includes:
- Standard CCM: Basic Chaotic Cat Map encryption
- Enhanced CCM (ECCM): Improved version with:
  * Key-dependent permutation matrices
  * Bidirectional diffusion
  * Image-salted chaotic sequences
  * Round-specific key derivation
"""

from .ccm_encryption import ChaoticCatMapEncryption
from .ccm_color import ColorImageEncryption
from .eccm_encryption import EnhancedChaoticCatMap, EnhancedColorEncryption

__all__ = [
    'ChaoticCatMapEncryption',
    'ColorImageEncryption',
    'EnhancedChaoticCatMap',
    'EnhancedColorEncryption'
]

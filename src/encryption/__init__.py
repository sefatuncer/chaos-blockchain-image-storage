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
- C4 Protocol: Cross-Channel Chaotic Coupling for color images
- Key Rotation: Secure key rotation with forward/backward secrecy
"""

from .ccm_encryption import ChaoticCatMapEncryption
from .ccm_color import ColorImageEncryption
from .eccm_encryption import EnhancedChaoticCatMap, EnhancedColorEncryption
from .c4_protocol import CrossChannelChaoticCoupling, compare_c4_vs_independent
from .key_rotation import (
    KeyRotationManager,
    RotationRequest,
    RotationStatus,
    ShareUpdateProof,
    RotationSecurityVerifier
)

__all__ = [
    # Standard CCM
    'ChaoticCatMapEncryption',
    'ColorImageEncryption',
    # Enhanced CCM
    'EnhancedChaoticCatMap',
    'EnhancedColorEncryption',
    # C4 Protocol
    'CrossChannelChaoticCoupling',
    'compare_c4_vs_independent',
    # Key Rotation
    'KeyRotationManager',
    'RotationRequest',
    'RotationStatus',
    'ShareUpdateProof',
    'RotationSecurityVerifier'
]

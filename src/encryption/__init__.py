"""
Chaotic Cat Map (CCM) Image Encryption Module

This module implements chaos-based image encryption using the Arnold Cat Map
transformation for secure medical image storage.
"""

from .ccm_encryption import ChaoticCatMapEncryption
from .ccm_color import ColorImageEncryption

__all__ = ['ChaoticCatMapEncryption', 'ColorImageEncryption']

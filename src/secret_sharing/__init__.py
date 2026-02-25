"""
Secret Sharing Module

Implements:
- Shamir's (k,n) threshold secret sharing scheme for secure key distribution
- Adaptive Threshold Algorithm (ATA) for dynamic threshold adjustment
"""

from .shamir import ShamirSecretSharing, KeyShareManager
from .adaptive_threshold import (
    AdaptiveThresholdAlgorithm,
    AccessContext,
    ThresholdDecision,
    RiskLevel,
    ATASecurityVerifier
)

__all__ = [
    'ShamirSecretSharing',
    'KeyShareManager',
    'AdaptiveThresholdAlgorithm',
    'AccessContext',
    'ThresholdDecision',
    'RiskLevel',
    'ATASecurityVerifier'
]

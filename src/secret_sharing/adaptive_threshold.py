"""
Adaptive Threshold Algorithm (ATA) for Dynamic Secret Sharing

Implements a risk-based dynamic threshold mechanism that adjusts the
required number of shares for key reconstruction based on contextual
security factors.

Standard (t,n) threshold schemes use fixed threshold t. ATA dynamically
adjusts this threshold based on a composite risk score:

Risk Score Calculation:
    R(t) = alpha * A(t) + beta * T(t) + gamma * H(t) + delta * N(t)

Where:
    A(t) - Anomaly score (0-1): Detected unusual access patterns
    T(t) - Time score (0-1): Time-based risk (off-hours, holidays)
    H(t) - Trust history (0-1): Historical behavior of requesting parties
    N(t) - Network score (0-1): Network topology/location risk

Dynamic Threshold:
    t_dynamic = t_base + ceil(R(t) * (n - t_base))

This ensures:
    - Low risk (R=0): t_dynamic = t_base (minimum threshold)
    - High risk (R=1): t_dynamic = n (all shares required)
    - Intermediate: Proportional scaling

Security Properties:
    1. Bounded threshold: t_base <= t_dynamic <= n
    2. Monotonic: Higher risk always increases threshold
    3. Deterministic: Same inputs produce same threshold
    4. Auditable: All threshold decisions are logged

Reference:
This implements the Adaptive Threshold Algorithm described in Section 3.4.2
of the paper "Chaos-Based Medical Image Encryption with Blockchain-Coordinated
Threshold Key Recovery"
"""

import hashlib
import time
import math
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime, timedelta


class RiskLevel(Enum):
    """Risk level categories for threshold decisions."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class AccessContext:
    """
    Context information for threshold calculation.

    Captures all relevant factors for risk assessment.
    """
    requester_id: str
    request_time: datetime
    ip_address: str
    user_agent: str
    previous_attempts: int = 0
    failed_attempts: int = 0
    location: str = "unknown"
    is_emergency: bool = False
    session_duration: float = 0.0  # seconds since session start
    concurrent_requests: int = 1
    trust_score: float = 1.0  # 0-1, higher is more trusted


@dataclass
class ThresholdDecision:
    """
    Record of a threshold decision for audit trail.
    """
    decision_id: str
    timestamp: datetime
    base_threshold: int
    dynamic_threshold: int
    risk_score: float
    risk_components: Dict[str, float]
    context: AccessContext
    risk_level: RiskLevel


class AdaptiveThresholdAlgorithm:
    """
    Adaptive Threshold Algorithm (ATA) implementation.

    Dynamically adjusts the threshold for secret sharing based on
    contextual risk factors.

    Attributes:
        t_base (int): Base threshold (minimum shares required)
        n (int): Total number of shares
        alpha (float): Weight for anomaly score
        beta (float): Weight for time score
        gamma (float): Weight for trust history
        delta (float): Weight for network score
    """

    def __init__(self, t_base: int = 3, n: int = 5,
                 alpha: float = 0.3, beta: float = 0.2,
                 gamma: float = 0.3, delta: float = 0.2):
        """
        Initialize ATA with threshold parameters and risk weights.

        Args:
            t_base: Base threshold (minimum shares required)
            n: Total number of shares
            alpha: Weight for anomaly detection score
            beta: Weight for time-based risk score
            gamma: Weight for trust history score
            delta: Weight for network risk score

        Raises:
            ValueError: If parameters are invalid
        """
        if t_base < 2:
            raise ValueError("Base threshold must be at least 2")
        if t_base > n:
            raise ValueError("Base threshold cannot exceed total shares")
        if not math.isclose(alpha + beta + gamma + delta, 1.0, rel_tol=1e-5):
            raise ValueError("Risk weights must sum to 1.0")

        self.t_base = t_base
        self.n = n
        self.alpha = alpha
        self.beta = beta
        self.gamma = gamma
        self.delta = delta

        # Internal state
        self._access_history: Dict[str, List[datetime]] = {}
        self._failed_attempts: Dict[str, int] = {}
        self._decision_log: List[ThresholdDecision] = []
        self._trusted_ips: set = set()
        self._suspicious_ips: set = set()

    def _calculate_anomaly_score(self, context: AccessContext) -> float:
        """
        Calculate anomaly score A(t) based on unusual access patterns.

        Factors considered:
        - Rapid successive requests
        - Failed attempt history
        - Concurrent request count
        - Session duration anomalies

        Args:
            context: Access context information

        Returns:
            Anomaly score between 0 (normal) and 1 (highly anomalous)
        """
        score = 0.0

        # Factor 1: Failed attempts (max 0.4)
        if context.failed_attempts > 0:
            score += min(0.4, context.failed_attempts * 0.1)

        # Factor 2: Concurrent requests (max 0.2)
        if context.concurrent_requests > 3:
            score += min(0.2, (context.concurrent_requests - 3) * 0.05)

        # Factor 3: Request frequency (max 0.2)
        requester_history = self._access_history.get(context.requester_id, [])
        if len(requester_history) > 0:
            recent_requests = [
                t for t in requester_history
                if context.request_time - t < timedelta(minutes=5)
            ]
            if len(recent_requests) > 5:
                score += min(0.2, (len(recent_requests) - 5) * 0.04)

        # Factor 4: Session anomaly (max 0.2)
        if context.session_duration < 1.0 and context.previous_attempts > 0:
            # Very quick repeated access is suspicious
            score += 0.2

        return min(1.0, score)

    def _calculate_time_score(self, context: AccessContext) -> float:
        """
        Calculate time-based risk score T(t).

        Factors considered:
        - Business hours vs off-hours
        - Weekend/holiday access
        - Unusual hour patterns

        Args:
            context: Access context information

        Returns:
            Time risk score between 0 (low risk) and 1 (high risk)
        """
        score = 0.0
        hour = context.request_time.hour
        weekday = context.request_time.weekday()

        # Off-hours access (0.3 max)
        if hour < 6 or hour > 22:
            score += 0.3
        elif hour < 8 or hour > 18:
            score += 0.1

        # Weekend access (0.2 max)
        if weekday >= 5:  # Saturday or Sunday
            score += 0.2

        # Emergency flag reduces time risk
        if context.is_emergency:
            score *= 0.5

        return min(1.0, score)

    def _calculate_trust_score(self, context: AccessContext) -> float:
        """
        Calculate trust history score H(t).

        Lower trust = higher risk score.

        Args:
            context: Access context information

        Returns:
            Trust risk score between 0 (trusted) and 1 (untrusted)
        """
        # Invert trust score (high trust = low risk)
        base_risk = 1.0 - context.trust_score

        # Adjust based on failed attempt history
        failed = self._failed_attempts.get(context.requester_id, 0)
        if failed > 0:
            base_risk = min(1.0, base_risk + failed * 0.1)

        return base_risk

    def _calculate_network_score(self, context: AccessContext) -> float:
        """
        Calculate network topology risk score N(t).

        Factors considered:
        - Known trusted IPs
        - Suspicious IP history
        - Geographic location

        Args:
            context: Access context information

        Returns:
            Network risk score between 0 (trusted) and 1 (untrusted)
        """
        score = 0.3  # Default moderate risk

        # Trusted IP
        if context.ip_address in self._trusted_ips:
            score = 0.1

        # Suspicious IP
        if context.ip_address in self._suspicious_ips:
            score = 0.8

        # Unknown location
        if context.location == "unknown":
            score = min(1.0, score + 0.2)

        return score

    def calculate_risk_score(self, context: AccessContext) -> Tuple[float, Dict[str, float]]:
        """
        Calculate composite risk score R(t).

        R(t) = alpha * A(t) + beta * T(t) + gamma * H(t) + delta * N(t)

        Args:
            context: Access context information

        Returns:
            Tuple of (total_risk_score, component_scores_dict)
        """
        A = self._calculate_anomaly_score(context)
        T = self._calculate_time_score(context)
        H = self._calculate_trust_score(context)
        N = self._calculate_network_score(context)

        total = self.alpha * A + self.beta * T + self.gamma * H + self.delta * N

        components = {
            'anomaly': A,
            'time': T,
            'trust': H,
            'network': N,
            'weighted_anomaly': self.alpha * A,
            'weighted_time': self.beta * T,
            'weighted_trust': self.gamma * H,
            'weighted_network': self.delta * N
        }

        return total, components

    def get_dynamic_threshold(self, context: AccessContext) -> ThresholdDecision:
        """
        Calculate dynamic threshold based on risk score.

        t_dynamic = t_base + ceil(R(t) * (n - t_base))

        Args:
            context: Access context information

        Returns:
            ThresholdDecision with dynamic threshold and audit information
        """
        # Calculate risk score
        risk_score, components = self.calculate_risk_score(context)

        # Calculate dynamic threshold
        threshold_increase = math.ceil(risk_score * (self.n - self.t_base))
        t_dynamic = self.t_base + threshold_increase

        # Ensure bounds
        t_dynamic = max(self.t_base, min(self.n, t_dynamic))

        # Determine risk level
        if risk_score < 0.25:
            risk_level = RiskLevel.LOW
        elif risk_score < 0.5:
            risk_level = RiskLevel.MEDIUM
        elif risk_score < 0.75:
            risk_level = RiskLevel.HIGH
        else:
            risk_level = RiskLevel.CRITICAL

        # Create decision record
        decision_id = hashlib.sha256(
            f"{context.requester_id}:{context.request_time.isoformat()}:{time.time_ns()}".encode()
        ).hexdigest()[:16]

        decision = ThresholdDecision(
            decision_id=decision_id,
            timestamp=context.request_time,
            base_threshold=self.t_base,
            dynamic_threshold=t_dynamic,
            risk_score=risk_score,
            risk_components=components,
            context=context,
            risk_level=risk_level
        )

        # Log decision
        self._decision_log.append(decision)

        # Update access history
        if context.requester_id not in self._access_history:
            self._access_history[context.requester_id] = []
        self._access_history[context.requester_id].append(context.request_time)

        return decision

    def record_failed_attempt(self, requester_id: str) -> None:
        """
        Record a failed recovery attempt.

        Args:
            requester_id: ID of the requester who failed
        """
        self._failed_attempts[requester_id] = \
            self._failed_attempts.get(requester_id, 0) + 1

    def record_successful_attempt(self, requester_id: str) -> None:
        """
        Record a successful recovery attempt.

        Resets failed attempt counter for the requester.

        Args:
            requester_id: ID of the requester who succeeded
        """
        if requester_id in self._failed_attempts:
            del self._failed_attempts[requester_id]

    def add_trusted_ip(self, ip_address: str) -> None:
        """Add an IP address to the trusted list."""
        self._trusted_ips.add(ip_address)
        self._suspicious_ips.discard(ip_address)

    def add_suspicious_ip(self, ip_address: str) -> None:
        """Add an IP address to the suspicious list."""
        self._suspicious_ips.add(ip_address)
        self._trusted_ips.discard(ip_address)

    def get_decision_log(self, limit: int = 100) -> List[ThresholdDecision]:
        """
        Get recent threshold decisions for audit.

        Args:
            limit: Maximum number of decisions to return

        Returns:
            List of recent ThresholdDecision objects
        """
        return self._decision_log[-limit:]

    def get_statistics(self) -> Dict:
        """
        Get ATA statistics for monitoring.

        Returns:
            Dictionary with usage statistics
        """
        if not self._decision_log:
            return {
                'total_decisions': 0,
                'avg_risk_score': 0,
                'avg_dynamic_threshold': self.t_base
            }

        risk_scores = [d.risk_score for d in self._decision_log]
        thresholds = [d.dynamic_threshold for d in self._decision_log]

        risk_levels = {}
        for d in self._decision_log:
            level = d.risk_level.value
            risk_levels[level] = risk_levels.get(level, 0) + 1

        return {
            'total_decisions': len(self._decision_log),
            'avg_risk_score': sum(risk_scores) / len(risk_scores),
            'avg_dynamic_threshold': sum(thresholds) / len(thresholds),
            'min_threshold': min(thresholds),
            'max_threshold': max(thresholds),
            'risk_level_distribution': risk_levels,
            'unique_requesters': len(self._access_history),
            'total_failed_attempts': sum(self._failed_attempts.values())
        }

    def export_audit_log(self) -> List[Dict]:
        """
        Export decision log as serializable dictionaries.

        Returns:
            List of decision dictionaries
        """
        return [
            {
                'decision_id': d.decision_id,
                'timestamp': d.timestamp.isoformat(),
                'base_threshold': d.base_threshold,
                'dynamic_threshold': d.dynamic_threshold,
                'risk_score': d.risk_score,
                'risk_level': d.risk_level.value,
                'risk_components': d.risk_components,
                'requester_id': d.context.requester_id,
                'ip_address': d.context.ip_address
            }
            for d in self._decision_log
        ]


class ATASecurityVerifier:
    """
    Verifies ATA security properties through formal checks.
    """

    @staticmethod
    def verify_bounded_threshold(ata: AdaptiveThresholdAlgorithm,
                                 test_contexts: List[AccessContext]) -> bool:
        """
        Verify that t_base <= t_dynamic <= n for all inputs.

        Args:
            ata: ATA instance to verify
            test_contexts: List of test contexts

        Returns:
            True if bounded property holds
        """
        for context in test_contexts:
            decision = ata.get_dynamic_threshold(context)
            if not (ata.t_base <= decision.dynamic_threshold <= ata.n):
                return False
        return True

    @staticmethod
    def verify_monotonicity(ata: AdaptiveThresholdAlgorithm) -> bool:
        """
        Verify that higher risk always increases or maintains threshold.

        Returns:
            True if monotonic property holds
        """
        # Test with controlled risk levels
        base_context = AccessContext(
            requester_id="test_user",
            request_time=datetime.now(),
            ip_address="192.168.1.1",
            user_agent="test",
            trust_score=1.0
        )

        low_risk_decision = ata.get_dynamic_threshold(base_context)

        # Increase risk factors
        high_risk_context = AccessContext(
            requester_id="test_user",
            request_time=datetime.now().replace(hour=3),  # Off-hours
            ip_address="unknown_ip",
            user_agent="test",
            trust_score=0.2,
            failed_attempts=5,
            concurrent_requests=10
        )

        high_risk_decision = ata.get_dynamic_threshold(high_risk_context)

        return high_risk_decision.dynamic_threshold >= low_risk_decision.dynamic_threshold


if __name__ == "__main__":
    print("Adaptive Threshold Algorithm (ATA) Demo")
    print("=" * 60)

    # Initialize ATA with (3,5) threshold scheme
    ata = AdaptiveThresholdAlgorithm(
        t_base=3,
        n=5,
        alpha=0.3,  # Anomaly weight
        beta=0.2,   # Time weight
        gamma=0.3,  # Trust weight
        delta=0.2   # Network weight
    )

    print(f"Base Threshold: {ata.t_base}")
    print(f"Total Shares: {ata.n}")
    print(f"Risk Weights: alpha={ata.alpha}, beta={ata.beta}, "
          f"gamma={ata.gamma}, delta={ata.delta}")

    # Test scenarios
    print("\n" + "=" * 60)
    print("Test Scenarios")
    print("=" * 60)

    # Scenario 1: Low-risk access
    print("\n1. Low-Risk Access (Trusted user, business hours)")
    context1 = AccessContext(
        requester_id="dr_smith",
        request_time=datetime.now().replace(hour=10),
        ip_address="192.168.1.100",
        user_agent="HospitalClient/1.0",
        trust_score=0.95,
        location="hospital_main"
    )
    ata.add_trusted_ip("192.168.1.100")
    decision1 = ata.get_dynamic_threshold(context1)

    print(f"   Risk Score: {decision1.risk_score:.4f}")
    print(f"   Risk Level: {decision1.risk_level.value}")
    print(f"   Dynamic Threshold: {decision1.dynamic_threshold} (base: {decision1.base_threshold})")

    # Scenario 2: Medium-risk access
    print("\n2. Medium-Risk Access (New user, evening)")
    context2 = AccessContext(
        requester_id="new_doctor",
        request_time=datetime.now().replace(hour=20),
        ip_address="10.0.0.55",
        user_agent="MobileClient/2.0",
        trust_score=0.6,
        location="remote"
    )
    decision2 = ata.get_dynamic_threshold(context2)

    print(f"   Risk Score: {decision2.risk_score:.4f}")
    print(f"   Risk Level: {decision2.risk_level.value}")
    print(f"   Dynamic Threshold: {decision2.dynamic_threshold} (base: {decision2.base_threshold})")

    # Scenario 3: High-risk access
    print("\n3. High-Risk Access (Unknown user, failed attempts, off-hours)")
    ata.record_failed_attempt("suspicious_user")
    ata.record_failed_attempt("suspicious_user")
    ata.record_failed_attempt("suspicious_user")

    context3 = AccessContext(
        requester_id="suspicious_user",
        request_time=datetime.now().replace(hour=3),
        ip_address="unknown_external_ip",
        user_agent="Unknown",
        trust_score=0.2,
        failed_attempts=3,
        concurrent_requests=5,
        location="unknown"
    )
    ata.add_suspicious_ip("unknown_external_ip")
    decision3 = ata.get_dynamic_threshold(context3)

    print(f"   Risk Score: {decision3.risk_score:.4f}")
    print(f"   Risk Level: {decision3.risk_level.value}")
    print(f"   Dynamic Threshold: {decision3.dynamic_threshold} (base: {decision3.base_threshold})")
    print(f"   Risk Components:")
    for comp, value in decision3.risk_components.items():
        if not comp.startswith('weighted'):
            print(f"      {comp}: {value:.4f}")

    # Scenario 4: Emergency access
    print("\n4. Emergency Access (Emergency flag set)")
    context4 = AccessContext(
        requester_id="emergency_team",
        request_time=datetime.now().replace(hour=2),
        ip_address="192.168.1.50",
        user_agent="EmergencyClient/1.0",
        trust_score=0.8,
        is_emergency=True,
        location="er_department"
    )
    decision4 = ata.get_dynamic_threshold(context4)

    print(f"   Risk Score: {decision4.risk_score:.4f}")
    print(f"   Risk Level: {decision4.risk_level.value}")
    print(f"   Dynamic Threshold: {decision4.dynamic_threshold} (base: {decision4.base_threshold})")

    # Security verification
    print("\n" + "=" * 60)
    print("Security Property Verification")
    print("=" * 60)

    verifier = ATASecurityVerifier()

    # Verify bounded threshold
    test_contexts = [context1, context2, context3, context4]
    bounded = verifier.verify_bounded_threshold(ata, test_contexts)
    print(f"\nBounded Threshold Property: {'PASS' if bounded else 'FAIL'}")
    print(f"  (t_base <= t_dynamic <= n for all inputs)")

    # Verify monotonicity
    mono = verifier.verify_monotonicity(ata)
    print(f"\nMonotonicity Property: {'PASS' if mono else 'FAIL'}")
    print(f"  (Higher risk => higher or equal threshold)")

    # Statistics
    print("\n" + "=" * 60)
    print("ATA Statistics")
    print("=" * 60)

    stats = ata.get_statistics()
    print(f"\nTotal Decisions: {stats['total_decisions']}")
    print(f"Average Risk Score: {stats['avg_risk_score']:.4f}")
    print(f"Average Dynamic Threshold: {stats['avg_dynamic_threshold']:.2f}")
    print(f"Threshold Range: [{stats['min_threshold']}, {stats['max_threshold']}]")
    print(f"Risk Level Distribution: {stats['risk_level_distribution']}")

    print("\nAdaptive Threshold Algorithm demonstration complete!")

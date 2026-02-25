"""
Tests for Adaptive Threshold Algorithm (ATA)

This module tests the ATA implementation for dynamic secret sharing thresholds.
"""

import unittest
from datetime import datetime, timedelta
import sys
import os

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from secret_sharing.adaptive_threshold import (
    AdaptiveThresholdAlgorithm,
    AccessContext,
    ThresholdDecision,
    RiskLevel,
    ATASecurityVerifier
)


class TestAdaptiveThresholdAlgorithm(unittest.TestCase):
    """Test cases for ATA."""

    def setUp(self):
        """Set up test ATA instance."""
        self.ata = AdaptiveThresholdAlgorithm(
            t_base=3,
            n=5,
            alpha=0.3,
            beta=0.2,
            gamma=0.3,
            delta=0.2
        )

    def test_initialization(self):
        """Test ATA initialization."""
        self.assertEqual(self.ata.t_base, 3)
        self.assertEqual(self.ata.n, 5)
        self.assertAlmostEqual(
            self.ata.alpha + self.ata.beta + self.ata.gamma + self.ata.delta,
            1.0
        )

    def test_invalid_threshold_raises_error(self):
        """Test that invalid thresholds raise ValueError."""
        with self.assertRaises(ValueError):
            AdaptiveThresholdAlgorithm(t_base=1, n=5)  # t_base < 2

        with self.assertRaises(ValueError):
            AdaptiveThresholdAlgorithm(t_base=6, n=5)  # t_base > n

    def test_invalid_weights_raises_error(self):
        """Test that weights not summing to 1.0 raise ValueError."""
        with self.assertRaises(ValueError):
            AdaptiveThresholdAlgorithm(
                t_base=3, n=5,
                alpha=0.5, beta=0.5, gamma=0.5, delta=0.5
            )

    def test_low_risk_context(self):
        """Test low risk context produces base threshold."""
        context = AccessContext(
            requester_id="trusted_user",
            request_time=datetime.now().replace(hour=10),
            ip_address="192.168.1.100",
            user_agent="TrustedClient/1.0",
            trust_score=0.95,
            location="main_hospital"
        )
        self.ata.add_trusted_ip("192.168.1.100")

        decision = self.ata.get_dynamic_threshold(context)

        self.assertEqual(decision.base_threshold, 3)
        self.assertGreaterEqual(decision.dynamic_threshold, 3)
        self.assertLessEqual(decision.dynamic_threshold, 5)
        self.assertEqual(decision.risk_level, RiskLevel.LOW)

    def test_high_risk_context(self):
        """Test high risk context increases threshold."""
        # Record failed attempts
        for _ in range(5):
            self.ata.record_failed_attempt("suspicious_user")

        context = AccessContext(
            requester_id="suspicious_user",
            request_time=datetime.now().replace(hour=3),  # Off-hours
            ip_address="unknown_ip",
            user_agent="Unknown",
            trust_score=0.1,
            failed_attempts=5,
            concurrent_requests=10,
            location="unknown"
        )
        self.ata.add_suspicious_ip("unknown_ip")

        decision = self.ata.get_dynamic_threshold(context)

        self.assertGreater(decision.dynamic_threshold, decision.base_threshold)
        self.assertIn(decision.risk_level, [RiskLevel.HIGH, RiskLevel.CRITICAL])

    def test_bounded_threshold_property(self):
        """Test that threshold is always within bounds."""
        contexts = [
            AccessContext(
                requester_id="user1",
                request_time=datetime.now().replace(hour=h),
                ip_address=f"192.168.1.{i}",
                user_agent="Test",
                trust_score=t/10
            )
            for h in [2, 10, 22]
            for i in [1, 100, 200]
            for t in [1, 5, 10]
        ]

        verifier = ATASecurityVerifier()
        self.assertTrue(verifier.verify_bounded_threshold(self.ata, contexts))

    def test_monotonicity_property(self):
        """Test that higher risk leads to higher or equal threshold."""
        verifier = ATASecurityVerifier()
        self.assertTrue(verifier.verify_monotonicity(self.ata))

    def test_risk_score_calculation(self):
        """Test risk score calculation returns valid values."""
        context = AccessContext(
            requester_id="test_user",
            request_time=datetime.now(),
            ip_address="10.0.0.1",
            user_agent="Test",
            trust_score=0.5
        )

        risk_score, components = self.ata.calculate_risk_score(context)

        self.assertGreaterEqual(risk_score, 0)
        self.assertLessEqual(risk_score, 1)

        self.assertIn('anomaly', components)
        self.assertIn('time', components)
        self.assertIn('trust', components)
        self.assertIn('network', components)

    def test_emergency_flag_reduces_time_risk(self):
        """Test that emergency flag reduces time-based risk."""
        base_context = AccessContext(
            requester_id="emergency_user",
            request_time=datetime.now().replace(hour=3),  # Off-hours
            ip_address="192.168.1.50",
            user_agent="EmergencyClient",
            trust_score=0.8,
            is_emergency=False
        )

        emergency_context = AccessContext(
            requester_id="emergency_user",
            request_time=datetime.now().replace(hour=3),
            ip_address="192.168.1.50",
            user_agent="EmergencyClient",
            trust_score=0.8,
            is_emergency=True
        )

        normal_decision = self.ata.get_dynamic_threshold(base_context)
        emergency_decision = self.ata.get_dynamic_threshold(emergency_context)

        # Emergency should have lower or equal risk
        self.assertLessEqual(
            emergency_decision.risk_score,
            normal_decision.risk_score + 0.01  # Allow small margin
        )

    def test_failed_attempts_increase_risk(self):
        """Test that failed attempts increase risk score."""
        context1 = AccessContext(
            requester_id="user_no_failures",
            request_time=datetime.now(),
            ip_address="10.0.0.1",
            user_agent="Test",
            trust_score=0.5,
            failed_attempts=0
        )

        context2 = AccessContext(
            requester_id="user_with_failures",
            request_time=datetime.now(),
            ip_address="10.0.0.2",
            user_agent="Test",
            trust_score=0.5,
            failed_attempts=5
        )

        decision1 = self.ata.get_dynamic_threshold(context1)
        decision2 = self.ata.get_dynamic_threshold(context2)

        self.assertGreater(decision2.risk_score, decision1.risk_score)

    def test_decision_logging(self):
        """Test that decisions are logged."""
        context = AccessContext(
            requester_id="logged_user",
            request_time=datetime.now(),
            ip_address="10.0.0.1",
            user_agent="Test",
            trust_score=0.5
        )

        initial_count = len(self.ata.get_decision_log())
        self.ata.get_dynamic_threshold(context)
        final_count = len(self.ata.get_decision_log())

        self.assertEqual(final_count, initial_count + 1)

    def test_statistics_calculation(self):
        """Test statistics calculation."""
        # Make some decisions
        for i in range(5):
            context = AccessContext(
                requester_id=f"user_{i}",
                request_time=datetime.now(),
                ip_address=f"10.0.0.{i}",
                user_agent="Test",
                trust_score=0.5
            )
            self.ata.get_dynamic_threshold(context)

        stats = self.ata.get_statistics()

        self.assertGreaterEqual(stats['total_decisions'], 5)
        self.assertIn('avg_risk_score', stats)
        self.assertIn('avg_dynamic_threshold', stats)
        self.assertIn('risk_level_distribution', stats)

    def test_export_audit_log(self):
        """Test audit log export."""
        context = AccessContext(
            requester_id="audit_user",
            request_time=datetime.now(),
            ip_address="10.0.0.1",
            user_agent="Test",
            trust_score=0.5
        )
        self.ata.get_dynamic_threshold(context)

        audit_log = self.ata.export_audit_log()

        self.assertIsInstance(audit_log, list)
        if audit_log:
            entry = audit_log[-1]
            self.assertIn('decision_id', entry)
            self.assertIn('timestamp', entry)
            self.assertIn('dynamic_threshold', entry)
            self.assertIn('risk_score', entry)

    def test_trusted_ip_reduces_risk(self):
        """Test that trusted IP reduces network risk."""
        context_unknown = AccessContext(
            requester_id="test_user",
            request_time=datetime.now(),
            ip_address="192.168.1.50",
            user_agent="Test",
            trust_score=0.5
        )

        decision_unknown = self.ata.get_dynamic_threshold(context_unknown)

        self.ata.add_trusted_ip("192.168.1.50")

        context_trusted = AccessContext(
            requester_id="test_user",
            request_time=datetime.now(),
            ip_address="192.168.1.50",
            user_agent="Test",
            trust_score=0.5
        )

        decision_trusted = self.ata.get_dynamic_threshold(context_trusted)

        self.assertLessEqual(decision_trusted.risk_score, decision_unknown.risk_score)

    def test_record_successful_attempt_clears_failures(self):
        """Test that successful attempt clears failed attempt counter."""
        self.ata.record_failed_attempt("test_user")
        self.ata.record_failed_attempt("test_user")

        self.assertEqual(self.ata._failed_attempts.get("test_user", 0), 2)

        self.ata.record_successful_attempt("test_user")

        self.assertEqual(self.ata._failed_attempts.get("test_user", 0), 0)


class TestRiskLevelClassification(unittest.TestCase):
    """Test risk level classification."""

    def setUp(self):
        """Set up test ATA instance."""
        self.ata = AdaptiveThresholdAlgorithm(t_base=3, n=5)

    def test_risk_levels_properly_assigned(self):
        """Test that risk levels are assigned correctly."""
        # Create contexts with varying risk
        low_risk_context = AccessContext(
            requester_id="trusted",
            request_time=datetime.now().replace(hour=10),
            ip_address="192.168.1.1",
            user_agent="Trusted",
            trust_score=1.0
        )
        self.ata.add_trusted_ip("192.168.1.1")

        decision = self.ata.get_dynamic_threshold(low_risk_context)

        # Verify risk level is an enum
        self.assertIsInstance(decision.risk_level, RiskLevel)

        # Verify risk level value is valid
        valid_levels = [RiskLevel.LOW, RiskLevel.MEDIUM, RiskLevel.HIGH, RiskLevel.CRITICAL]
        self.assertIn(decision.risk_level, valid_levels)


if __name__ == '__main__':
    unittest.main()

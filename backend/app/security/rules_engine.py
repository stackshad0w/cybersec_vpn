from typing import List, Dict, Any, Optional
from backend.app.models.finding import FindingSeverity, FindingCategory
from backend.app.models.ipsec import EvidenceStatus
from backend.app.schemas.policy import SecurityPolicyConfig

class RuleResult:
    def __init__(
        self,
        dimension: str,
        score: float,  # 0.0 to 100.0
        findings: List[Dict[str, Any]]
    ):
        self.dimension = dimension
        self.score = score
        self.findings = findings

class SecurityRulesEngine:
    """
    Deterministic security rules engine for IPsec/IKE/ESP security audits.
    Checks crypto, DH groups, PFS, anti-replay, protocol version, and lifetimes.
    """

    @classmethod
    def evaluate(
        cls,
        ike_sessions: List[Dict[str, Any]],
        esp_sessions: List[Dict[str, Any]],
        policy: Optional[SecurityPolicyConfig] = None
    ) -> Dict[str, RuleResult]:
        if policy is None:
            policy = SecurityPolicyConfig()

        results = {}
        results["cryptography"] = cls._evaluate_cryptography(ike_sessions, policy)
        results["key_exchange"] = cls._evaluate_key_exchange(ike_sessions, policy)
        results["authentication"] = cls._evaluate_authentication(ike_sessions, policy)
        results["pfs"] = cls._evaluate_pfs(ike_sessions, policy)
        results["replay_protection"] = cls._evaluate_replay(esp_sessions, policy)
        results["sa_configuration"] = cls._evaluate_sa_config(ike_sessions, policy)
        results["protocol"] = cls._evaluate_protocol(ike_sessions, policy)
        results["metadata_exposure"] = cls._evaluate_metadata(ike_sessions, esp_sessions)

        return results

    @classmethod
    def _evaluate_cryptography(cls, ike_sessions: List[Dict[str, Any]], policy: SecurityPolicyConfig) -> RuleResult:
        findings = []
        score = 100.0

        if not ike_sessions:
            return RuleResult("cryptography", 70.0, [{
                "title": "Unobservable IKE Cryptographic Suite",
                "category": FindingCategory.CRYPTOGRAPHY,
                "severity": FindingSeverity.LOW,
                "evidence_status": EvidenceStatus.NOT_OBSERVABLE.value,
                "evidence": "Capture contains ESP data flows without initial IKE negotiation packets.",
                "impact": "Cryptographic transform parameters could not be verified directly from IKE proposals.",
                "recommendation": "Capture initial IKE_SA_INIT handshake to verify symmetric cipher suites.",
                "remediation_command": None
            }])

        for ike in ike_sessions:
            prop = ike.get("proposals", {}) if isinstance(ike, dict) else {}
            enc = (ike.get("encryption_algorithm") or prop.get("encryption") or "").upper()
            integ = (ike.get("integrity_algorithm") or prop.get("integrity") or "").upper()

            # Cipher evaluation
            if "DES" in enc and "3DES" not in enc:
                score = min(score, 10.0)
                findings.append({
                    "title": "Critical Vulnerability: Obsolete Single DES Encryption",
                    "category": FindingCategory.CRYPTOGRAPHY,
                    "severity": FindingSeverity.CRITICAL,
                    "evidence_status": EvidenceStatus.VERIFIED.value,
                    "evidence": f"Negotiated cipher transform: {enc}",
                    "impact": "56-bit key space can be broken in hours using modern brute-force hardware.",
                    "recommendation": "Immediately migrate to AES-256-GCM or AES-128-GCM.",
                    "remediation_command": "strongSwan: ike=aes256gcm16-prfsha384-modp3072! / Cisco: crypto ikev2 proposal PROP encryption aes-gcm-256"
                })
            elif "3DES" in enc:
                score = min(score, 30.0)
                findings.append({
                    "title": "High Risk: Deprecated Triple-DES (3DES) Cipher Detected",
                    "category": FindingCategory.CRYPTOGRAPHY,
                    "severity": FindingSeverity.HIGH,
                    "evidence_status": EvidenceStatus.VERIFIED.value,
                    "evidence": f"Negotiated transform: {enc}",
                    "impact": "64-bit block size vulnerable to Sweet32 collision attacks (CVE-2016-2183).",
                    "recommendation": "Deprecate 3DES and transition to AES-GCM.",
                    "remediation_command": "Cisco: no crypto ipsec transform-set ESP-3DES-SHA / esp-gcm 256"
                })
            elif "AES-128-CBC" in enc:
                score = min(score, 75.0)
                findings.append({
                    "title": "Acceptable: AES-128-CBC in Use",
                    "category": FindingCategory.CRYPTOGRAPHY,
                    "severity": FindingSeverity.LOW,
                    "evidence_status": EvidenceStatus.VERIFIED.value,
                    "evidence": f"Negotiated transform: {enc}",
                    "impact": "CBC mode requires separate HMAC integrity check and is susceptible to padding oracle flaws if improperly implemented.",
                    "recommendation": "Consider upgrading to authenticated AEAD ciphers like AES-256-GCM.",
                    "remediation_command": "strongSwan: esp=aes256gcm16-modp2048!"
                })
            elif "AES-256-GCM" in enc or "CHACHA20" in enc:
                findings.append({
                    "title": "Strong Cryptography: Authenticated AES-GCM / ChaCha20",
                    "category": FindingCategory.CRYPTOGRAPHY,
                    "severity": FindingSeverity.INFO,
                    "evidence_status": EvidenceStatus.VERIFIED.value,
                    "evidence": f"Observed modern AEAD cipher transform: {enc}",
                    "impact": "Provides high performance and verified AEAD authentication against tampering.",
                    "recommendation": "Maintain current cipher configuration.",
                    "remediation_command": None
                })

            # Integrity evaluation
            if "MD5" in integ:
                score = min(score, 20.0)
                findings.append({
                    "title": "Critical Risk: Broken MD5 Integrity Hash",
                    "category": FindingCategory.CRYPTOGRAPHY,
                    "severity": FindingSeverity.CRITICAL,
                    "evidence_status": EvidenceStatus.VERIFIED.value,
                    "evidence": f"Negotiated integrity algorithm: {integ}",
                    "impact": "Practical hash collision vulnerabilities undermine message authenticity.",
                    "recommendation": "Replace MD5 with SHA-256 or use AEAD cipher suites.",
                    "remediation_command": "Cisco: integrity sha256"
                })
            elif "SHA1" in integ:
                score = min(score, 50.0)
                findings.append({
                    "title": "Medium Risk: Legacy SHA-1 Integrity Algorithm",
                    "category": FindingCategory.CRYPTOGRAPHY,
                    "severity": FindingSeverity.MEDIUM,
                    "evidence_status": EvidenceStatus.VERIFIED.value,
                    "evidence": f"Negotiated integrity algorithm: {integ}",
                    "impact": "NIST has deprecated SHA-1 for digital signatures and secure protocols.",
                    "recommendation": "Upgrade to HMAC-SHA-256 or HMAC-SHA-384.",
                    "remediation_command": "strongSwan: esp=aes256-sha256!"
                })

        return RuleResult("cryptography", score, findings)

    @classmethod
    def _evaluate_key_exchange(cls, ike_sessions: List[Dict[str, Any]], policy: SecurityPolicyConfig) -> RuleResult:
        findings = []
        score = 100.0

        if not ike_sessions:
            return RuleResult("key_exchange", 70.0, [])

        for ike in ike_sessions:
            prop = ike.get("proposals", {}) if isinstance(ike, dict) else {}
            group_num = ike.get("dh_group_number") or prop.get("dh_group_num")
            group_name = ike.get("dh_group") or prop.get("dh_group") or (f"Group {group_num}" if group_num else None)
            if not group_num and group_name:
                # Try to extract number if string contains e.g. Group 19 or Group 2
                import re
                m = re.search(r"Group\s+(\d+)", group_name)
                if m:
                    group_num = int(m.group(1))

            if group_num in (1, 2):
                score = min(score, 25.0)
                findings.append({
                    "title": f"Critical Weakness: Deprecated Diffie-Hellman {group_name}",
                    "category": FindingCategory.KEY_EXCHANGE,
                    "severity": FindingSeverity.CRITICAL,
                    "evidence_status": EvidenceStatus.VERIFIED.value,
                    "evidence": f"Observed DH Transform: {group_name} (Group {group_num})",
                    "impact": "1024-bit and smaller discrete log groups are vulnerable to precomputation attacks (Logjam).",
                    "recommendation": "Upgrade DH group to at least Group 14 (2048-bit MODP) or Group 19/20 (ECP).",
                    "remediation_command": "Cisco: crypto ikev2 proposal PROP group 19 20 14 / strongSwan: ike=...-modp2048"
                })
            elif group_num == 5:
                score = min(score, 60.0)
                findings.append({
                    "title": "Legacy Diffie-Hellman Group 5 (1536-bit)",
                    "category": FindingCategory.KEY_EXCHANGE,
                    "severity": FindingSeverity.MEDIUM,
                    "evidence_status": EvidenceStatus.VERIFIED.value,
                    "evidence": f"Observed DH Transform: {group_name}",
                    "impact": "1536-bit modulus offers ~96-bit security margin, below standard 128-bit modern requirements.",
                    "recommendation": "Migrate to Group 14 (2048-bit) or Elliptic Curve Group 19/21.",
                    "remediation_command": "strongSwan: dhgroup=ecp256"
                })
            elif group_num in (14, 15, 16, 19, 20, 21, 31):
                findings.append({
                    "title": f"Strong Key Exchange: {group_name}",
                    "category": FindingCategory.KEY_EXCHANGE,
                    "severity": FindingSeverity.INFO,
                    "evidence_status": EvidenceStatus.VERIFIED.value,
                    "evidence": f"DH group {group_num} exceeds NIST minimum key size recommendations.",
                    "impact": "Provides robust resistance against state-level cryptanalysis.",
                    "recommendation": "Maintain modern DH configuration.",
                    "remediation_command": None
                })

        return RuleResult("key_exchange", score, findings)

    @classmethod
    def _evaluate_authentication(cls, ike_sessions: List[Dict[str, Any]], policy: SecurityPolicyConfig) -> RuleResult:
        findings = []
        score = 85.0

        for ike in ike_sessions:
            auth_method = ike.get("auth_method") or "Pre-Shared Key / Digital Signature"
            # If IKEv1 Aggressive mode was observed, pre-shared key hashes are sent in cleartext
            if ike.get("version") == "IKEv1" and ike.get("exchange_type") == 4:
                score = min(score, 20.0)
                findings.append({
                    "title": "Severe Flaw: IKEv1 Aggressive Mode with PSK",
                    "category": FindingCategory.AUTHENTICATION,
                    "severity": FindingSeverity.CRITICAL,
                    "evidence_status": EvidenceStatus.VERIFIED.value,
                    "evidence": "IKEv1 Exchange Type 4 (Aggressive Mode) observed.",
                    "impact": "PSK authentication hash is transmitted in cleartext and vulnerable to offline dictionary/rainbow table recovery.",
                    "recommendation": "Switch immediately to IKEv2 with RSA-PSS/ECDSA certificate authentication.",
                    "remediation_command": "Cisco: crypto ikev2 profile PROF / authentication remote rsa-sig"
                })

        return RuleResult("authentication", score, findings)

    @classmethod
    def _evaluate_pfs(cls, ike_sessions: List[Dict[str, Any]], policy: SecurityPolicyConfig) -> RuleResult:
        findings = []
        pfs_detected = any(
            bool(ike.get("pfs_enabled") or (ike.get("proposals", {}) if isinstance(ike, dict) else {}).get("pfs_enabled"))
            for ike in ike_sessions
        )

        if pfs_detected:
            score = 100.0
            findings.append({
                "title": "Perfect Forward Secrecy (PFS) Active",
                "category": FindingCategory.PFS,
                "severity": FindingSeverity.INFO,
                "evidence_status": EvidenceStatus.VERIFIED.value,
                "evidence": "Observed explicit Diffie-Hellman exchange during Child SA negotiation.",
                "impact": "Compromise of long-term credentials does not expose past encrypted tunnel sessions.",
                "recommendation": "Retain PFS enforcement.",
                "remediation_command": None
            })
        else:
            score = 65.0
            findings.append({
                "title": "PFS (Perfect Forward Secrecy) Not Confirmed",
                "category": FindingCategory.PFS,
                "severity": FindingSeverity.MEDIUM,
                "evidence_status": EvidenceStatus.POTENTIAL_INFERRED.value,
                "evidence": "Child SA negotiation did not explicitly include independent DH transforms in observed exchange.",
                "impact": "If private keys are compromised, historical traffic captures may be decrypted retrospectively.",
                "recommendation": "Explicitly enable PFS in IPsec Child SA profiles.",
                "remediation_command": "Cisco: set pfs group19 / strongSwan: esp=aes256gcm16-modp2048!"
            })

        return RuleResult("pfs", score, findings)

    @classmethod
    def _evaluate_replay(cls, esp_sessions: List[Dict[str, Any]], policy: SecurityPolicyConfig) -> RuleResult:
        findings = []
        score = 100.0

        if not esp_sessions:
            return RuleResult("replay_protection", 80.0, [])

        any_duplicates = False
        for esp in esp_sessions:
            dup_count = esp.get("duplicate_sequences_count", 0)
            pkt_count = esp.get("packet_count", 0)

            if dup_count > 0:
                any_duplicates = True
                score = min(score, 30.0)
                findings.append({
                    "title": "Critical: Duplicate ESP Sequence Numbers Observed (Replay Attack)",
                    "category": FindingCategory.REPLAY_PROTECTION,
                    "severity": FindingSeverity.CRITICAL,
                    "evidence_status": EvidenceStatus.VERIFIED.value,
                    "evidence": f"Found {dup_count} duplicate sequence numbers across {pkt_count} ESP packets.",
                    "impact": "Active replay attack in progress or anti-replay window disabled on endpoint.",
                    "recommendation": "Ensure anti-replay window is strictly enforced on gateways.",
                    "remediation_command": "Cisco: crypto ipsec security-association replay window-size 1024"
                })

        if not any_duplicates and esp_sessions:
            total_pkts = sum(esp.get("packet_count", 0) for esp in esp_sessions)
            findings.append({
                "title": "Anti-Replay Protection Validated",
                "category": FindingCategory.REPLAY_PROTECTION,
                "severity": FindingSeverity.INFO,
                "evidence_status": EvidenceStatus.VERIFIED.value,
                "evidence": f"Strictly monotonic sequence numbers with zero duplicates across {total_pkts} packets.",
                "impact": "Defends against packet replay attacks.",
                "recommendation": "Maintain replay window enforcement.",
                "remediation_command": None
            })

        return RuleResult("replay_protection", score, findings)

    @classmethod
    def _evaluate_sa_config(cls, ike_sessions: List[Dict[str, Any]], policy: SecurityPolicyConfig) -> RuleResult:
        findings = []
        score = 90.0

        for ike in ike_sessions:
            lifetime = ike.get("sa_lifetime_seconds")
            if lifetime and lifetime > policy.max_sa_lifetime_seconds:
                score = min(score, 60.0)
                findings.append({
                    "title": f"Excessive SA Lifetime ({lifetime}s)",
                    "category": FindingCategory.SA_LIFETIME,
                    "severity": FindingSeverity.MEDIUM,
                    "evidence_status": EvidenceStatus.VERIFIED.value,
                    "evidence": f"Configured SA lifetime is {lifetime}s (policy limit: {policy.max_sa_lifetime_seconds}s).",
                    "impact": "Extends window for cryptanalysis and key leakage.",
                    "recommendation": "Reduce SA lifetime to 28,800 seconds (8 hours) or less.",
                    "remediation_command": "strongSwan: lifetime = 8h / Cisco: crypto ipsec security-association lifetime seconds 28800"
                })

        return RuleResult("sa_configuration", score, findings)

    @classmethod
    def _evaluate_protocol(cls, ike_sessions: List[Dict[str, Any]], policy: SecurityPolicyConfig) -> RuleResult:
        findings = []
        score = 100.0

        for ike in ike_sessions:
            version = ike.get("version")
            if version == "IKEv1":
                score = min(score, 45.0)
                findings.append({
                    "title": "Deprecated Protocol: IKEv1 Detected",
                    "category": FindingCategory.PROTOCOL,
                    "severity": FindingSeverity.HIGH,
                    "evidence_status": EvidenceStatus.VERIFIED.value,
                    "evidence": "Observed IKEv1 protocol headers.",
                    "impact": "IKEv1 is officially deprecated by IETF (RFC 9395) due to vulnerability to DDoS amplification and MITM flaws.",
                    "recommendation": "Upgrade all peer endpoints to IKEv2.",
                    "remediation_command": "Cisco: crypto ikev2 enable <interface>"
                })

        return RuleResult("protocol", score, findings)

    @classmethod
    def _evaluate_metadata(cls, ike_sessions: List[Dict[str, Any]], esp_sessions: List[Dict[str, Any]]) -> RuleResult:
        findings = []
        score = 85.0
        # Check if cleartext identities or NAT-T disclosures are present
        for ike in ike_sessions:
            if ike.get("nat_traversal_detected"):
                findings.append({
                    "title": "NAT-Traversal Active on UDP 4500",
                    "category": FindingCategory.METADATA_LEAK,
                    "severity": FindingSeverity.INFO,
                    "evidence_status": EvidenceStatus.VERIFIED.value,
                    "evidence": "IKE/ESP packets encapsulated over UDP port 4500 with Non-ESP marker.",
                    "impact": "Allows VPN traversal across stateful NAT firewalls.",
                    "recommendation": "Ensure NAT keepalive intervals do not leak traffic periodicity.",
                    "remediation_command": None
                })
        return RuleResult("metadata_exposure", score, findings)

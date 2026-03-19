"""
Framework mapping data for redis-stig-audit.

Provides NIST SP 800-171 Rev 2, CMMC 2.0, MITRE ATT&CK, and MITRE D3FEND
mappings for each Redis audit control (keyed by check_id).

Mapping rationale
-----------------
NIST 800-171 Rev 2 (110 controls / 14 families) — derived from the NIST
  SP 800-171 Rev 2 Appendix D cross-reference to NIST SP 800-53 Rev 4/5.

CMMC 2.0 levels:
  Level 1 — 17 "basic safeguarding" practices (subset of FAR 52.204-21 + 800-171)
  Level 2 — all 110 NIST SP 800-171 Rev 2 practices
  Level 3 — NIST SP 800-172 additions (24+ enhanced practices)

MITRE ATT&CK — Enterprise / Containers matrix; only techniques with a
  direct defensive relationship to the control are listed.

MITRE D3FEND — Defensive countermeasure knowledge graph (d3fend.mitre.org);
  only D3FEND techniques the control actively implements are listed.

Key 800-53 → 800-171 cross-references used:
  AC-2, AC-3, AC-6  → 3.1.1, 3.1.2, 3.1.5, 3.1.6
  AU-2, AU-3, AU-12 → 3.3.1, 3.3.2
  CM-2, CM-3, CM-6, CM-7 → 3.4.1, 3.4.2, 3.4.3, 3.4.6, 3.4.7
  CP-9              → 3.8.9
  IA-5              → 3.5.3, 3.5.7, 3.5.8, 3.5.10
  SC-7, SC-8        → 3.13.1, 3.13.5, 3.13.8
  SI-2, SI-7        → 3.14.1
"""

# ---------------------------------------------------------------------------
# Per-control framework data
# Key: check_id (string, must match checks/*.py)
# Value: dict with keys: nist_800_171, cmmc_level, mitre_attack, mitre_d3fend
# ---------------------------------------------------------------------------
FRAMEWORK_MAP: dict[str, dict] = {

    # ------------------------------------------------------------------ #
    # Section 2 – Core Redis Configuration (via config.py)
    # ------------------------------------------------------------------ #

    "RD-CFG-001": {
        # Keep protected mode enabled (benchmark 2.4)
        # 800-53: SC-7 → 800-171: 3.13.1 (monitor/control communications at external boundaries)
        # CMMC L1: 3.13.1 is one of the 17 Level 1 basic-safeguarding practices
        "nist_800_171": ["3.13.1"],
        "cmmc_level": 1,
        # T1133: External Remote Services — protected mode guards unauthenticated external access
        # T1190: Exploit Public-Facing Application — unprotected Redis reachable from untrusted nets
        "mitre_attack": ["T1133", "T1190"],
        # D3-NI: Network Isolation — protected mode acts as last-resort network guard
        # D3-ACH: Application Configuration Hardening
        "mitre_d3fend": ["D3-NI", "D3-ACH"],
    },

    "RD-CFG-002": {
        # Bind Redis only to trusted interfaces (benchmark 2.5)
        # 800-53: SC-7 → 800-171: 3.13.1, 3.13.5 (subnetworks for publicly accessible components)
        # CMMC L1: 3.13.1 is Level 1; 3.13.5 is Level 2 — lowest satisfied is L1
        "nist_800_171": ["3.13.1", "3.13.5"],
        "cmmc_level": 1,
        # T1133: External Remote Services — broad bind exposes Redis to unauthorized clients
        "mitre_attack": ["T1133"],
        # D3-NI: Network Isolation
        # D3-NTF: Network Traffic Filtering
        "mitre_d3fend": ["D3-NI", "D3-NTF"],
    },

    "RD-CFG-003": {
        # Enable TLS where Redis traffic crosses trust boundaries (benchmark 3.1)
        # 800-53: SC-8 → 800-171: 3.13.8 (cryptographic mechanisms to prevent disclosure in transit)
        # CMMC L2
        "nist_800_171": ["3.13.8"],
        "cmmc_level": 2,
        # T1040: Network Sniffing — TLS prevents credential/data interception
        "mitre_attack": ["T1040"],
        # D3-ET: Encrypted Tunnels — TLS for in-transit protection
        # D3-MH: Message Hardening — encrypted transport layer
        "mitre_d3fend": ["D3-ET", "D3-MH"],
    },

    "RD-CFG-004": {
        # Restrict default-user broad access and prefer ACL-based least privilege (benchmark 2.2)
        # 800-53: AC-2, AC-3, AC-6 → 800-171: 3.1.1, 3.1.2, 3.1.5
        # CMMC L1: 3.1.1, 3.1.2, 3.1.5 are Level 1 practices
        "nist_800_171": ["3.1.1", "3.1.2", "3.1.5"],
        "cmmc_level": 1,
        # T1078: Valid Accounts — default nopass user is exploitable without credentials
        # T1078.001: Default Accounts — Redis ships with a permissive default user
        # T1098: Account Manipulation — overly broad default user enables privilege manipulation
        "mitre_attack": ["T1078", "T1078.001", "T1098"],
        # D3-UAP: User Account Permissions — ACLs scope per-user access
        # D3-RBAC: Role-Based Access Control
        "mitre_d3fend": ["D3-UAP", "D3-RBAC"],
    },

    "RD-CFG-005": {
        # Restrict dangerous administrative commands (benchmark 2.3)
        # 800-53: CM-7, AC-6 → 800-171: 3.4.6 (least functionality), 3.4.7 (restrict nonessential services), 3.1.5
        # CMMC L2: 3.4.6, 3.4.7 are Level 2
        "nist_800_171": ["3.4.6", "3.4.7", "3.1.5"],
        "cmmc_level": 2,
        # T1609: Container Administration Command — CONFIG/MODULE/DEBUG enable runtime manipulation
        # T1485: Data Destruction — FLUSHALL/FLUSHDB destroy all data
        "mitre_attack": ["T1609", "T1485"],
        # D3-ACH: Application Configuration Hardening — command renaming/disabling
        "mitre_d3fend": ["D3-ACH"],
    },

    "RD-CFG-006": {
        # Configure persistence intentionally (benchmark 4.1)
        # 800-53: CP-9 → 800-171: 3.8.9 (protect backup CUI at storage locations)
        # CMMC L2
        "nist_800_171": ["3.8.9"],
        "cmmc_level": 2,
        # T1485: Data Destruction — accidental persistence misconfiguration may lead to data loss
        "mitre_attack": ["T1485"],
        # D3-ACH: Application Configuration Hardening — deliberate persistence configuration
        "mitre_d3fend": ["D3-ACH"],
    },

    "RD-CFG-007": {
        # Persist ACL configuration outside ad hoc runtime state (benchmark 2.2b)
        # 800-53: CM-3, AC-2 → 800-171: 3.4.3 (track/review/approve config changes), 3.1.1
        # CMMC L2
        "nist_800_171": ["3.4.3", "3.1.1"],
        "cmmc_level": 2,
        # T1098: Account Manipulation — ephemeral ACL state makes unauthorized changes hard to detect
        "mitre_attack": ["T1098"],
        # D3-ACH: Application Configuration Hardening — durable/auditable config
        "mitre_d3fend": ["D3-ACH"],
    },

    "RD-CFG-008": {
        # Secure replication paths with TLS where replication is in use (benchmark 5.1)
        # 800-53: SC-8, SC-7 → 800-171: 3.13.8
        # CMMC L2
        "nist_800_171": ["3.13.8"],
        "cmmc_level": 2,
        # T1040: Network Sniffing — unencrypted replication streams expose all cached data
        "mitre_attack": ["T1040"],
        # D3-ET: Encrypted Tunnels — TLS for replication/cluster links
        "mitre_d3fend": ["D3-ET"],
    },

    "RD-CFG-009": {
        # Disable plaintext Redis listeners when TLS-only posture is required (benchmark 3.1b)
        # 800-53: SC-8 → 800-171: 3.13.8
        # CMMC L2
        "nist_800_171": ["3.13.8"],
        "cmmc_level": 2,
        # T1040: Network Sniffing — dual plaintext+TLS listeners allow downgrade
        "mitre_attack": ["T1040"],
        # D3-ET: Encrypted Tunnels
        # D3-ACH: Application Configuration Hardening
        "mitre_d3fend": ["D3-ET", "D3-ACH"],
    },

    "RD-CFG-010": {
        # Configure Redis logging intentionally (benchmark 4.3)
        # 800-53: AU-2, AU-12 → 800-171: 3.3.1 (create/retain audit records), 3.3.2 (trace user actions)
        # CMMC L2
        "nist_800_171": ["3.3.1", "3.3.2"],
        "cmmc_level": 2,
        # T1562.001: Disable or Modify Tools — inadequate logging enables detection evasion
        "mitre_attack": ["T1562.001"],
        # D3-ALCA: Application Log Audit
        "mitre_d3fend": ["D3-ALCA"],
    },

    # ------------------------------------------------------------------ #
    # Section 2 – Authentication (via auth.py)
    # ------------------------------------------------------------------ #

    "RD-AUTH-001": {
        # Require authenticated administrative access (benchmark 2.1)
        # 800-53: AC-6, IA-5 → 800-171: 3.1.5, 3.5.3, 3.5.7
        # CMMC L1: 3.1.5 (least privilege) is a Level 1 practice
        "nist_800_171": ["3.1.5", "3.5.3", "3.5.7"],
        "cmmc_level": 1,
        # T1078: Valid Accounts — no password = zero barrier to administrative access
        # T1078.001: Default Accounts — Redis default user has no password by default
        # T1110: Brute Force — absent auth makes brute force moot (already open)
        "mitre_attack": ["T1078", "T1078.001", "T1110"],
        # D3-SPP: Strong Password Policy
        # D3-UAP: User Account Permissions
        "mitre_d3fend": ["D3-SPP", "D3-UAP"],
    },

    # ------------------------------------------------------------------ #
    # Section 8 – Runtime Metadata (via runtime.py)
    # ------------------------------------------------------------------ #

    "RD-RT-001": {
        # Collect Redis runtime server metadata for audit traceability (benchmark 8.0)
        # 800-53: AU-3 → 800-171: 3.3.1 (content of audit records)
        # CMMC L2 (AU-3 maps to 3.3.1 which is L2)
        "nist_800_171": ["3.3.1"],
        "cmmc_level": 2,
        # No direct ATT&CK technique — this is an observability/evidence control
        "mitre_attack": [],
        # D3-ALCA: Application Log Audit — runtime metadata supports audit traceability
        "mitre_d3fend": ["D3-ALCA"],
    },

    "RD-RT-002": {
        # Capture replication role for topology-aware assessment (benchmark 5.1)
        # 800-53: SC-7, SC-8 → 800-171: 3.13.1, 3.13.8
        # CMMC L2 (topology-aware security assessment)
        "nist_800_171": ["3.13.1", "3.13.8"],
        "cmmc_level": 2,
        "mitre_attack": [],
        # D3-ALCA: Application Log Audit
        "mitre_d3fend": ["D3-ALCA"],
    },

    "RD-RT-003": {
        # Capture persistence runtime health for recoverability evidence (benchmark 4.1b)
        # 800-53: CP-9, AU-3 → 800-171: 3.8.9, 3.3.1
        # CMMC L2
        "nist_800_171": ["3.8.9", "3.3.1"],
        "cmmc_level": 2,
        # T1485: Data Destruction — failing persistence jobs may indicate tampering or data loss
        "mitre_attack": ["T1485"],
        # D3-ALCA: Application Log Audit
        "mitre_d3fend": ["D3-ALCA"],
    },

    # ------------------------------------------------------------------ #
    # Section 6/7 – Container Runtime Hardening (via container.py)
    # ------------------------------------------------------------------ #

    "RD-CONT-001": {
        # Verify Redis process runs as a non-root user (benchmark 6.1)
        # 800-53: AC-6, CM-7 → 800-171: 3.1.5, 3.1.6, 3.4.6
        # CMMC L1: 3.1.5 (least privilege) is Level 1
        "nist_800_171": ["3.1.5", "3.1.6", "3.4.6"],
        "cmmc_level": 1,
        # T1611: Escape to Host — root in container enables escape via kernel vulnerabilities
        # T1068: Exploitation for Privilege Escalation — root UID amplifies exploit impact
        "mitre_attack": ["T1611", "T1068"],
        # D3-CH: Container Hardening
        # D3-UAP: User Account Permissions
        "mitre_d3fend": ["D3-CH", "D3-UAP"],
    },

    "RD-CONT-002": {
        # Prevent privileged containers (benchmark 7.2)
        # 800-53: CM-6 → 800-171: 3.4.2 (security configuration settings)
        # CMMC L2
        "nist_800_171": ["3.4.2", "3.4.6"],
        "cmmc_level": 2,
        # T1611: Escape to Host — privileged containers have full access to host
        "mitre_attack": ["T1611"],
        # D3-CH: Container Hardening
        "mitre_d3fend": ["D3-CH"],
    },

    "RD-CONT-003": {
        # Drop unnecessary Linux capabilities (benchmark 7.1)
        # 800-53: CM-6, CM-7 → 800-171: 3.4.6, 3.4.7
        # CMMC L2
        "nist_800_171": ["3.4.6", "3.4.7"],
        "cmmc_level": 2,
        # T1611: Escape to Host — excess capabilities (NET_ADMIN, SYS_ADMIN) enable container escape
        "mitre_attack": ["T1611"],
        # D3-CH: Container Hardening
        # D3-PH: Platform Hardening — restrict host kernel call surface
        "mitre_d3fend": ["D3-CH", "D3-PH"],
    },

    "RD-CONT-004": {
        # Use read-only root filesystems (benchmark 7.3)
        # 800-53: CM-6 → 800-171: 3.4.2
        # CMMC L2
        "nist_800_171": ["3.4.2"],
        "cmmc_level": 2,
        # T1611: Escape to Host — writable root FS enables persistence and escape mechanisms
        # T1014: Rootkit — attacker installs rootkits / backdoors on writable FS
        "mitre_attack": ["T1611", "T1014"],
        # D3-CH: Container Hardening
        # D3-PH: Platform Hardening
        "mitre_d3fend": ["D3-CH", "D3-PH"],
    },

    "RD-CONT-005": {
        # Set memory/CPU resource limits (benchmark 7.5)
        # 800-53: CM-6 → 800-171: 3.4.2
        # CMMC L2
        "nist_800_171": ["3.4.2"],
        "cmmc_level": 2,
        # T1499: Endpoint Denial of Service — unbounded resources enable noisy-neighbor / DoS
        "mitre_attack": ["T1499"],
        # D3-CH: Container Hardening
        # D3-PH: Platform Hardening
        "mitre_d3fend": ["D3-CH", "D3-PH"],
    },

    "RD-CONT-006": {
        # Restrict host namespace sharing (hostNetwork/hostPID/hostIPC) (benchmark 7.4)
        # 800-53: CM-6, AC-6 → 800-171: 3.4.2, 3.1.3, 3.1.5
        # CMMC L2
        "nist_800_171": ["3.4.2", "3.1.3", "3.1.5"],
        "cmmc_level": 2,
        # T1611: Escape to Host — host namespace sharing grants container extensive host visibility
        # T1049: System Network Connections Discovery — hostNetwork exposes host network
        "mitre_attack": ["T1611", "T1049"],
        # D3-CH: Container Hardening
        # D3-NI: Network Isolation
        "mitre_d3fend": ["D3-CH", "D3-NI"],
    },
}


def enrich(result) -> None:
    """
    Enrich a CheckResult in-place with NIST 800-171, CMMC, MITRE ATT&CK,
    and MITRE D3FEND data from the FRAMEWORK_MAP.

    Only sets values if the check_id is present in the map AND the field
    is currently empty (avoids overwriting manually-set values in check files).
    """
    data = FRAMEWORK_MAP.get(result.check_id)
    if not data:
        return
    if not result.nist_800_171:
        result.nist_800_171 = data.get("nist_800_171", [])
    if result.cmmc_level is None:
        result.cmmc_level = data.get("cmmc_level")
    if not result.mitre_attack:
        result.mitre_attack = data.get("mitre_attack", [])
    if not result.mitre_d3fend:
        result.mitre_d3fend = data.get("mitre_d3fend", [])


def enrich_all(results: list) -> list:
    """Enrich a list of CheckResult objects in-place; returns the same list."""
    for r in results:
        enrich(r)
    return results

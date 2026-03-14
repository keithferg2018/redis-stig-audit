# CIS-Style Benchmark Draft: Redis in Containers
## Version 0.2.0-draft | March 2026

---

## Preamble

### About This Benchmark

This benchmark provides prescriptive security configuration guidance for Redis deployed as container workloads in regulated environments, including FedRAMP-aligned annual security audit programs.

This document is **not** an official CIS Benchmark publication. It is a community draft modeled on CIS-style methodology to address a practical gap: Redis security guidance exists in fragments, but there is no widely adopted benchmark focused on **Redis operating inside containerized runtimes**.

This benchmark is intended to complement, not replace:
- CIS Docker Benchmark
- CIS Kubernetes Benchmark
- Redis official security guidance
- FedRAMP / NIST SP 800-53 control assessments

### Scope

This benchmark applies to:
- Redis OSS 6.x and 7.x
- Docker Engine and Docker Compose deployments
- Kubernetes / OpenShift style orchestrated deployments
- OCI-compatible runtimes such as containerd and CRI-O

Out of scope for the initial draft:
- managed Redis services where the operator does not control runtime configuration
- Redis Enterprise-specific controls
- non-container bare-metal or VM-only deployments

### Profile Definitions

- **Level 1**: Minimum recommended production baseline with low operational impact
- **Level 2**: Defense-in-depth controls recommended for sensitive or regulated environments

### Scoring

- **Scored**: Can be validated programmatically or through deterministic evidence
- **Not Scored**: Requires manual review, architectural review, or process validation

---

## Section 1: Container Image & Supply Chain Security

### 1.1 Use trusted Redis base images

**Profile:** Level 1 | **Scored**

#### Description
Only use Redis images sourced from the official Redis image stream or from an internal curated registry with documented provenance and vulnerability-management processes.

#### Rationale
Container image provenance is foundational. Even a correctly configured Redis runtime can be undermined if the image itself contains unauthorized modifications, embedded malware, or unmanaged package risk.

#### Impact
Low. This control primarily changes image sourcing discipline and artifact management.

#### Audit
```bash
# Docker / OCI
docker inspect <container> | jq '.[0].Config.Image'

docker image inspect <image> | jq '.[0].RepoTags, .[0].RepoDigests'

# Kubernetes
kubectl get pod <pod> -n <namespace> -o jsonpath='{.spec.containers[*].image}'
```

#### Remediation
- Use an official Redis image or a documented internal mirror.
- Block unreviewed third-party images from production deployment paths.
- Record image provenance in CI/CD or artifact metadata.

#### Default Value
Not enforced by default.

#### References
- Redis official deployment and security guidance
- NIST SP 800-190
- NIST SP 800-53 Rev 5: CM-6, SI-7

---

### 1.2 Pin Redis images to specific versions or digests

**Profile:** Level 1 | **Scored**

#### Description
Do not use mutable tags such as `latest` for production Redis images. Pin Redis images to a specific version tag, and prefer immutable digests in regulated environments.

#### Rationale
Mutable tags allow unreviewed runtime changes to enter production at pull time. Digest pinning improves immutability, traceability, and assessment repeatability.

#### Impact
Requires a deliberate image upgrade process.

#### Audit
```bash
# Docker
docker inspect <container> | jq '.[0].Config.Image'

# Kubernetes
kubectl get pods -A -o jsonpath='{range .items[*]}{.spec.containers[*].image}{"\n"}{end}'
```

#### Remediation
Use one of the following patterns:
```yaml
image: redis:7.2.4
```

```yaml
image: redis@sha256:<digest>
```

#### Default Value
If no tag is specified, container tooling may default to `latest`.

#### References
- NIST SP 800-190
- NIST SP 800-53 Rev 5: CM-2, CM-6

---

### 1.3 Scan Redis container images for known vulnerabilities before deployment

**Profile:** Level 1 | **Scored**

#### Description
Redis images must be scanned for known vulnerabilities before production deployment, with results integrated into a deployment approval or CI/CD gate.

#### Rationale
Redis container security is affected by both Redis-specific issues and OS/base-layer vulnerabilities.

#### Impact
Requires scanner integration and policy thresholds.

#### Audit
```bash
trivy image redis:7.2.4
# or
grype redis:7.2.4
```

#### Remediation
- Integrate image scanning into CI/CD
- Define block thresholds for critical/high vulnerabilities
- Document exceptions with compensating controls

#### Default Value
No scanning is performed by default.

#### References
- CIS Controls v8
- NIST SP 800-190
- NIST SP 800-53 Rev 5: SI-2, RA-5

---

### 1.4 Run Redis as a non-root user inside the container

**Profile:** Level 1 | **Scored**

#### Description
The Redis server process inside the container must not run as UID 0 (root).

#### Rationale
If Redis is compromised, root execution materially increases host and runtime risk, especially when combined with weak container isolation or misconfigured mounts.

#### Impact
Low for well-built images; moderate if custom images currently assume root.

#### Audit
```bash
docker exec <container> id
# Expected: non-root UID

kubectl exec -n <namespace> <pod> -- id
```

#### Remediation
- Set a non-root `USER` in the image, or
- use runtime security controls such as `runAsNonRoot`

#### Default Value
Varies by image and runtime.

#### References
- Redis security documentation recommends running as an unprivileged user
- NIST SP 800-53 Rev 5: CM-6

---

## Section 2: Core Redis Security Configuration

### 2.1 Require authenticated administrative access

**Profile:** Level 1 | **Scored**

#### Description
Administrative access to Redis must require authentication. Unauthenticated administrative access is prohibited.

#### Rationale
Redis was historically designed for trusted environments, but annual audit use in regulated spaces requires stronger assurance. Authentication provides a basic control layer if network protections fail.

#### Impact
Applications and operators must be updated to authenticate properly.

#### Audit
```bash
redis-cli -h <host> -p <port> ping
# Review whether commands are accepted without authentication

redis-cli -h <host> -p <port> ACL LIST
# if already authenticated
```

#### Remediation
- Use Redis ACLs for named users where supported
- If legacy `requirepass` is still in use, ensure it is strong and transitional rather than the final design target

#### Default Value
Default deployments may permit broad access via the default user if not hardened.

#### References
- Redis security docs
- Redis ACL docs
- NIST SP 800-53 Rev 5: AC-6, IA-5

---

### 2.2 Enable and enforce Redis ACLs

**Profile:** Level 2 | **Scored**

#### Description
Redis deployments should use ACLs to define named users with least-privilege command and key access.

#### Rationale
ACLs allow stronger role separation than shared passwords and reduce both malicious abuse and accidental operator error.

#### Impact
May require application and operational account redesign.

#### Audit
```bash
redis-cli ACL LIST
redis-cli ACL GETUSER <user>
```

#### Remediation
- Create named users for application, operator, and maintenance roles
- Restrict commands with ACL categories and command allow/deny rules
- Restrict keys and channels where feasible
- Avoid `nopass` and broad `+@all` access except where explicitly justified

#### Default Value
Backward-compatible default behavior may be overly permissive.

#### References
- Redis ACL documentation
- NIST SP 800-53 Rev 5: AC-2, AC-3, AC-6

---

### 2.3 Disable or tightly restrict dangerous administrative commands

**Profile:** Level 1 | **Scored**

#### Description
Dangerous administrative commands such as `FLUSHALL`, `FLUSHDB`, `CONFIG`, `MODULE`, `DEBUG`, and `SHUTDOWN` must be restricted to explicitly authorized users.

#### Rationale
These commands can destroy data, alter configuration, or materially change the runtime. Redis now recommends ACL-based restriction rather than relying on command renaming alone.

#### Impact
Requires role design and potentially operational workflow changes.

#### Audit
```bash
redis-cli ACL LIST
redis-cli COMMAND INFO FLUSHALL CONFIG MODULE DEBUG SHUTDOWN
```

#### Remediation
- Use ACLs to deny dangerous commands to application users
- Only allow such commands to tightly controlled administrative identities
- Avoid using deprecated command-renaming as the primary long-term control model

#### Default Value
Historically permissive if ACLs are not configured.

#### References
- Redis security docs
- Redis ACL docs
- NIST SP 800-53 Rev 5: CM-7, AC-6

---

### 2.4 Keep protected mode enabled unless equivalent compensating controls exist

**Profile:** Level 1 | **Scored**

#### Description
Protected mode should remain enabled unless the deployment documents equivalent compensating controls such as strict bind configuration, network isolation, and mandatory authentication.

#### Rationale
Protected mode exists specifically to reduce the risk of unintentionally exposed Redis instances.

#### Impact
Low in most secure deployments.

#### Audit
```bash
redis-cli CONFIG GET protected-mode
```

#### Remediation
- Leave `protected-mode yes` enabled by default
- If disabled, document and verify compensating controls

#### Default Value
Redis enables protected mode in insecure default exposure scenarios.

#### References
- Redis security docs
- NIST SP 800-53 Rev 5: SC-7

---

### 2.5 Bind only to trusted interfaces

**Profile:** Level 1 | **Scored**

#### Description
Redis must bind only to trusted interfaces and should never be broadly exposed to untrusted networks.

#### Rationale
Redis documentation explicitly assumes trusted environments. Public or overly broad exposure creates severe confidentiality, integrity, and availability risk.

#### Impact
May require application path or network redesign.

#### Audit
```bash
redis-cli CONFIG GET bind
ss -ltnp | grep 6379
kubectl get svc -A | grep redis
```

#### Remediation
- Bind to loopback or explicitly trusted interfaces where possible
- Use firewalls, security groups, and Kubernetes NetworkPolicy
- Avoid LoadBalancer / public ingress exposure without strong architectural justification

#### Default Value
May vary by image and runtime configuration.

#### References
- Redis security docs
- NIST SP 800-53 Rev 5: SC-7

---

## Section 3: Network & Transport Security

### 3.1 Encrypt Redis traffic in transit where sensitive data crosses trust boundaries

**Profile:** Level 2 | **Scored**

#### Description
Use TLS for Redis client, replication, and cluster traffic where data crosses trust boundaries or where regulated requirements demand transport protection.

#### Rationale
Redis traffic is not inherently encrypted. Passwords and data may be exposed to interception if transport protections are absent.

#### Impact
TLS introduces operational and performance overhead.

#### Audit
```bash
redis-cli CONFIG GET tls-port
redis-cli CONFIG GET port
redis-cli CONFIG GET tls-replication
redis-cli CONFIG GET tls-cluster
```

#### Remediation
- Configure `tls-port`
- Consider `port 0` where only TLS should be permitted
- Configure trusted CAs and certificates
- Enable `tls-replication yes` and `tls-cluster yes` where applicable

#### Default Value
TLS is optional and may not be enabled.

#### References
- Redis TLS documentation
- NIST SP 800-53 Rev 5: SC-8

---

### 3.2 Restrict ingress to trusted clients and management paths

**Profile:** Level 1 | **Scored**

Short form for now. Future versions should include full rationale/audit/remediation.

### 3.3 Do not expose Redis directly to the public Internet

**Profile:** Level 1 | **Scored**

Short form for now. Future versions should include full rationale/audit/remediation.

---

## Section 4: Persistence, Logging, and Auditability

### 4.1 Configure persistence intentionally
### 4.2 Protect Redis persistence files and mounted volumes
### 4.3 Enable sufficient logging for security operations
### 4.4 Centralize logs for annual audit evidence

---

## Section 5: High Availability / Replication Security

### 5.1 Secure replication paths
### 5.2 Restrict Sentinel / cluster administration exposure

---

## Section 6: Secrets & Credential Handling

### 6.1 Do not hardcode Redis secrets in container images
### 6.2 Avoid plaintext secrets in manifests when better secret stores are available
### 6.3 Rotate administrative and application credentials on a defined cadence

---

## Section 7: Container Runtime Hardening

### 7.1 Drop unnecessary Linux capabilities
### 7.2 Prevent privileged containers
### 7.3 Use read-only root filesystems where feasible
### 7.4 Restrict hostPath mounts and broad filesystem access
### 7.5 Set memory/CPU limits to reduce denial-of-service blast radius

---

## Section 8: FedRAMP / Evidence Mapping

This benchmark is intended to support evidence collection and recurring audit activity aligned with controls such as:
- AC-2, AC-3, AC-6
- AU-2, AU-3, AU-12
- CM-2, CM-6, CM-7
- IA-5
- SC-7, SC-8, SC-28
- SI-2, SI-4, SI-7

---

## Status

**Draft / community work-in-progress**

This document should be treated as an engineering and audit-assistance baseline pending deeper Redis-specific validation and broader community review.

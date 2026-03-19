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

#### Description
Redis network ingress must be limited to explicitly authorized clients and management sources. Network policies, security groups, or equivalent controls must prevent unauthorized hosts from reaching the Redis service port.

#### Rationale
Redis authentication alone does not prevent reconnaissance or connection-layer attacks. Network-layer restriction provides defense-in-depth and reduces exposure surface.

#### Impact
Requires coordination with network and infrastructure teams. May require firewall or Kubernetes NetworkPolicy configuration.

#### Audit
```bash
# Docker: check published ports
docker inspect <container> | jq '.[0].NetworkSettings.Ports'

# Kubernetes: review services and network policies
kubectl get svc -A | grep redis
kubectl get networkpolicy -A
```

#### Remediation
- Use Kubernetes `NetworkPolicy` to restrict ingress to Redis pods by namespace and pod selector
- Use Docker network isolation and avoid exposing Redis on host interfaces unless required
- Apply security groups or firewall rules in cloud environments
- Do not publish Redis ports directly to host unless an explicit, documented operational need exists

#### Default Value
No ingress restrictions are applied by default.

#### References
- Redis security docs
- NIST SP 800-53 Rev 5: SC-7, AC-17

---

### 3.3 Do not expose Redis directly to the public Internet

**Profile:** Level 1 | **Scored**

#### Description
Redis must never be directly accessible from the public Internet without explicit documented justification. Redis is not designed to operate in untrusted environments.

#### Rationale
Multiple Redis security incidents have involved publicly exposed instances. Redis's design assumes a trusted network context; Internet-facing exposure creates severe confidentiality, integrity, and availability risk.

#### Impact
Low for properly architected deployments. High remediation cost if Redis is currently Internet-facing.

#### Audit
```bash
# Check if Redis port is reachable from outside
nmap -p 6379 <public-ip>

# Check Docker port bindings (0.0.0.0 = all interfaces)
docker inspect <container> | jq '.[0].HostConfig.PortBindings'

# Check Kubernetes LoadBalancer services
kubectl get svc -A | grep -E 'LoadBalancer.*6379'
```

#### Remediation
- Never use `docker run -p 6379:6379` on a public-facing host without a firewall
- Do not create Kubernetes `LoadBalancer` services targeting Redis without strong justification
- Use Kubernetes `ClusterIP` services for Redis by default
- Apply cloud provider firewall rules to deny public access to Redis ports

#### Default Value
Not enforced by default. Depends on deployment configuration.

#### References
- Redis security docs
- NIST SP 800-53 Rev 5: SC-7

---

## Section 4: Persistence, Logging, and Auditability

### 4.1 Configure persistence intentionally

**Profile:** Level 1 | **Not Scored**

#### Description
Redis persistence mode (RDB snapshotting, AOF logging, or no persistence) must be explicitly chosen and documented based on data classification, recovery requirements, and operational risk tolerance.

#### Rationale
An undefined persistence posture creates ambiguity in data recovery planning. Unexpected AOF or RDB files may expose sensitive data if storage is not appropriately protected. Conversely, disabling persistence without documenting the decision may violate data protection requirements.

#### Impact
Low. Primarily a documentation and intent-verification requirement.

#### Audit
```bash
redis-cli CONFIG GET save
redis-cli CONFIG GET appendonly
redis-cli CONFIG GET appendfsync
```

#### Remediation
- Document the persistence mode chosen for each Redis deployment
- If persistence is disabled, confirm this is intentional and aligned with data classification (e.g., ephemeral cache only)
- If persistence is enabled, ensure backup and recovery procedures exist
- For regulated environments, prefer AOF with `appendfsync everysec` or `always` for auditability

#### Default Value
Redis defaults to RDB snapshotting with `save 3600 1 300 100 60 10000`.

#### References
- Redis persistence documentation
- NIST SP 800-53 Rev 5: CP-9

---

### 4.2 Protect Redis persistence files and mounted volumes

**Profile:** Level 1 | **Scored**

#### Description
Redis persistence files (RDB dumps and AOF logs) must be stored in volumes or paths with appropriate access controls and must not be accessible to unauthorized processes or users.

#### Rationale
RDB and AOF files contain serialized Redis data and may include sensitive application data. Unprotected persistence files expose data at rest.

#### Impact
Requires volume configuration review.

#### Audit
```bash
redis-cli CONFIG GET dir
redis-cli CONFIG GET dbfilename
redis-cli CONFIG GET appendfilename

# Docker: check mount points
docker inspect <container> | jq '.[0].Mounts'
```

#### Remediation
- Store persistence files on dedicated volumes with restricted permissions
- Ensure persistence volumes are not shared with other container workloads
- Use encrypted storage volumes in regulated environments
- Restrict directory permissions: `chmod 700 /data` (or equivalent)

#### Default Value
No volume protection is applied by default.

#### References
- NIST SP 800-53 Rev 5: SC-28, AC-3

---

### 4.3 Enable sufficient logging for security operations

**Profile:** Level 1 | **Scored**

#### Description
Redis logging must be configured at a level sufficient to support security operations and incident response, including connection events and error conditions.

#### Rationale
Redis does not natively support structured audit logging at the level of relational databases. Operational logging is the primary mechanism for detecting abnormal behavior.

#### Impact
Verbose logging may increase I/O load. Level `notice` or `verbose` is generally low impact.

#### Audit
```bash
redis-cli CONFIG GET loglevel
redis-cli CONFIG GET logfile
redis-cli CONFIG GET syslog-enabled
```

#### Remediation
- Set `loglevel notice` or `loglevel verbose` in regulated environments
- Configure `logfile` or `syslog-enabled yes` for persistent log capture
- Ensure log output is captured by the container runtime's logging driver

#### Default Value
`loglevel notice`. Logging may default to stdout only.

#### References
- Redis configuration documentation
- NIST SP 800-53 Rev 5: AU-2, AU-3, AU-12

---

### 4.4 Centralize logs for annual audit evidence

**Profile:** Level 1 | **Not Scored**

#### Description
Redis log output must be forwarded to a centralized log aggregation system to support security monitoring, incident response, and annual audit evidence collection.

#### Rationale
Container-local logs are ephemeral and inaccessible after container termination. Centralized logging is required for audit traceability and regulatory evidence.

#### Impact
Requires integration with a log aggregation platform (e.g., Splunk, ELK, Cloud Logging, Fluentd).

#### Audit
- Verify the container runtime logging driver is configured (e.g., `json-file`, `fluentd`, `awslogs`)
- Verify log forwarding is active in the environment's SIEM or log aggregation platform
- Document the log retention period and confirm it meets regulatory requirements (FedRAMP requires ≥90 days online, ≥1 year archived)

#### Remediation
- Configure Docker logging driver: `--log-driver json-file --log-opt max-size=10m` at minimum
- Use a sidecar or DaemonSet log forwarder in Kubernetes
- Validate that logs are received and indexed in the target SIEM

#### Default Value
No log forwarding is configured by default.

#### References
- NIST SP 800-53 Rev 5: AU-2, AU-9, SI-4
- FedRAMP log retention requirements

---

## Section 5: High Availability / Replication Security

### 5.1 Secure replication paths

**Profile:** Level 2 | **Scored**

#### Description
Redis replication traffic must be protected against eavesdropping and injection. Use TLS for replication where data sensitivity or network trust boundaries warrant transport protection.

#### Rationale
Redis replication transmits all data in plaintext by default. In environments where replication crosses untrusted network segments, this exposes both data and authentication credentials.

#### Impact
Requires TLS configuration on all nodes in the replication topology.

#### Audit
```bash
redis-cli CONFIG GET tls-replication
redis-cli INFO replication
```

#### Remediation
- Enable `tls-replication yes` when replication crosses trust boundaries
- Configure certificate and CA trust on all replica nodes
- Validate replication connectivity after TLS enablement

#### Default Value
`tls-replication no`.

#### References
- Redis TLS documentation
- NIST SP 800-53 Rev 5: SC-8

---

### 5.2 Restrict Sentinel / cluster administration exposure

**Profile:** Level 1 | **Scored**

#### Description
Redis Sentinel and Redis Cluster management interfaces must be restricted to authorized management systems. Sentinel ports and cluster bus ports must not be broadly exposed.

#### Rationale
Sentinel and cluster bus interfaces allow topology manipulation. Unauthorized access can enable failover manipulation, data exposure, or denial of service against the Redis topology.

#### Impact
Requires network policy configuration.

#### Audit
```bash
# Check Sentinel port binding
redis-cli -p 26379 SENTINEL masters 2>/dev/null || echo "Sentinel not exposed"

# Check cluster ports
redis-cli CONFIG GET cluster-enabled
redis-cli CONFIG GET cluster-announce-port
```

#### Remediation
- Apply network policies to restrict Sentinel ports (default 26379) to authorized monitoring and management hosts
- Apply network policies to restrict cluster bus ports (data port + 10000 by convention)
- Document all Sentinel and cluster bus access paths in the system security plan

#### Default Value
Cluster and Sentinel ports use no authentication by default in some configurations.

#### References
- Redis Sentinel documentation
- NIST SP 800-53 Rev 5: SC-7, AC-17

---

## Section 6: Secrets & Credential Handling

### 6.1 Do not hardcode Redis secrets in container images

**Profile:** Level 1 | **Scored**

#### Description
Redis passwords, ACL configurations, and TLS private keys must not be embedded in container images. Secrets must be injected at runtime via environment variables from a secrets management system, or via mounted secrets volumes.

#### Rationale
Container images are frequently pushed to registries and shared across teams. Hardcoded secrets in images create broad exposure risk and are difficult to rotate.

#### Impact
Requires secrets management integration.

#### Audit
```bash
# Check image build history for secret exposure
docker history <image> --no-trunc | grep -i -E 'pass|secret|key|token'

# Check environment variables for plaintext credentials
docker inspect <container> | jq '.[0].Config.Env'
```

#### Remediation
- Use Docker secrets, Kubernetes Secrets (with encryption-at-rest enabled), or external vaults (HashiCorp Vault, AWS Secrets Manager, GCP Secret Manager)
- Inject Redis passwords via environment variables sourced from a secrets store
- Do not use `ENV REDIS_PASSWORD=...` in Dockerfiles for production images

#### Default Value
No secrets management is enforced by default.

#### References
- NIST SP 800-53 Rev 5: IA-5, CM-6

---

### 6.2 Avoid plaintext secrets in manifests when better secret stores are available

**Profile:** Level 1 | **Scored**

#### Description
Redis connection secrets (passwords, TLS keys) must not be stored as plaintext in Kubernetes manifests, Helm values files, or Docker Compose files committed to version control.

#### Rationale
Plaintext secrets in manifests are often inadvertently committed to source control and exposed through repository access. Even when access is restricted, plaintext secrets in manifests create unnecessary risk.

#### Impact
Requires adoption of external secret injection (e.g., External Secrets Operator, Vault Agent Injector).

#### Audit
```bash
# Kubernetes: check if secrets are base64-only (not encrypted at rest)
kubectl get secret -A -o json | jq '.items[] | select(.type=="Opaque") | .metadata.name'

# Check if encryption at rest is configured
kubectl get apiserver -o json | jq '.spec.encryption'
```

#### Remediation
- Use Kubernetes Secrets with encryption at rest enabled
- Prefer external secret injection (External Secrets Operator, Vault Agent)
- Never commit `REDIS_PASSWORD=...` or equivalent to version control in plain text

#### Default Value
Kubernetes Secrets are base64-encoded but not encrypted at rest by default.

#### References
- NIST SP 800-53 Rev 5: IA-5, SC-28

---

### 6.3 Rotate administrative and application credentials on a defined cadence

**Profile:** Level 2 | **Not Scored**

#### Description
Redis ACL user passwords and administrative credentials must be rotated on a defined and documented cadence aligned with organizational security policy and regulatory requirements.

#### Rationale
Credential rotation limits the window of exposure if a credential is compromised. Unrotated credentials discovered in an incident may extend the attacker's access period significantly.

#### Impact
Requires an operational procedure and automation to avoid service disruption during rotation.

#### Audit
- Review organizational credential rotation policy
- Confirm Redis ACL users have associated rotation procedures
- Verify rotation has occurred within the required period (e.g., FedRAMP: typically ≤60 days for privileged credentials)

#### Remediation
- Define a rotation schedule for all Redis ACL users
- Automate rotation where possible using a secrets manager with dynamic credentials
- Test rotation procedures in non-production before applying to production
- Log rotation events for audit trail

#### Default Value
No automatic credential rotation is provided by Redis.

#### References
- NIST SP 800-53 Rev 5: IA-5(1)
- FedRAMP credential management requirements

---

## Section 7: Container Runtime Hardening

### 7.1 Drop unnecessary Linux capabilities

**Profile:** Level 1 | **Scored**

#### Description
The Redis container must drop all Linux capabilities not required for operation. Redis does not require elevated capabilities for normal operation.

#### Rationale
Linux capabilities provide granular privilege escalation paths. Dropping all unnecessary capabilities reduces the blast radius of container compromise.

#### Impact
Low. Redis does not require elevated capabilities for standard operation.

#### Audit
```bash
docker inspect <container> | jq '.[0].HostConfig.CapAdd, .[0].HostConfig.CapDrop'

# Kubernetes
kubectl get pod <pod> -o jsonpath='{.spec.containers[*].securityContext.capabilities}'
```

#### Remediation
```yaml
# Docker Compose
security_opt:
  - no-new-privileges:true
cap_drop:
  - ALL

# Kubernetes
securityContext:
  capabilities:
    drop: ["ALL"]
```

#### Default Value
No capabilities are dropped by default.

#### References
- CIS Docker Benchmark
- NIST SP 800-53 Rev 5: CM-7, AC-6

---

### 7.2 Prevent privileged containers

**Profile:** Level 1 | **Scored**

#### Description
The Redis container must not run in privileged mode. Privileged containers have full host access equivalent to root on the host system.

#### Rationale
Privileged containers negate most container isolation benefits. Redis does not require privileged mode for any operational purpose.

#### Impact
None. Redis operates correctly without privileged mode.

#### Audit
```bash
docker inspect <container> | jq '.[0].HostConfig.Privileged'
# Expected: false

kubectl get pod <pod> -o jsonpath='{.spec.containers[*].securityContext.privileged}'
# Expected: false or absent
```

#### Remediation
```yaml
# Docker Compose
privileged: false

# Kubernetes
securityContext:
  privileged: false
```

#### Default Value
`privileged: false`. Verify this has not been explicitly overridden.

#### References
- CIS Docker Benchmark
- NIST SP 800-53 Rev 5: CM-7

---

### 7.3 Use read-only root filesystems where feasible

**Profile:** Level 2 | **Scored**

#### Description
The Redis container root filesystem should be configured as read-only where operationally feasible, with explicit writable volume mounts for data and log directories.

#### Rationale
A read-only root filesystem prevents persistence of attacker-written files in the container filesystem and reduces the risk of configuration tampering.

#### Impact
Requires that all writable paths be explicitly mounted as volumes. AOF and RDB files must be on mounted volumes, not the container root.

#### Audit
```bash
docker inspect <container> | jq '.[0].HostConfig.ReadonlyRootfs'
# Expected: true

kubectl get pod <pod> -o jsonpath='{.spec.containers[*].securityContext.readOnlyRootFilesystem}'
```

#### Remediation
```yaml
# Docker Compose
read_only: true
volumes:
  - redis-data:/data

# Kubernetes
securityContext:
  readOnlyRootFilesystem: true
volumeMounts:
  - name: redis-data
    mountPath: /data
```

#### Default Value
Read-only root filesystem is not enabled by default.

#### References
- CIS Docker Benchmark
- NIST SP 800-53 Rev 5: CM-7, SI-7

---

### 7.4 Restrict hostPath mounts and broad filesystem access

**Profile:** Level 1 | **Scored**

#### Description
Redis containers must not mount host filesystem paths directly unless there is an explicit, documented operational requirement. `hostPath` mounts can expose host system files to the container.

#### Rationale
`hostPath` volumes bypass container filesystem isolation and can expose sensitive host files (e.g., `/etc/shadow`, `/var/run/docker.sock`) to the container.

#### Impact
Requires use of named volumes or Persistent Volume Claims instead of `hostPath` mounts.

#### Audit
```bash
docker inspect <container> | jq '.[0].HostConfig.Binds'
# Review for sensitive host paths

kubectl get pod <pod> -o jsonpath='{.spec.volumes}' | grep hostPath
```

#### Remediation
- Replace `hostPath` mounts with named Docker volumes or Kubernetes Persistent Volume Claims
- If `hostPath` is required, restrict to a specific, non-sensitive path and document the requirement
- Use Pod Security Admission policies to restrict `hostPath` in regulated clusters

#### Default Value
No restrictions are applied by default.

#### References
- CIS Kubernetes Benchmark
- NIST SP 800-53 Rev 5: AC-3, CM-7

---

### 7.5 Set memory/CPU limits to reduce denial-of-service blast radius

**Profile:** Level 1 | **Scored**

#### Description
Redis containers must have memory and CPU limits configured to prevent runaway memory consumption or CPU starvation from affecting other workloads on the same host.

#### Rationale
Redis is an in-memory data store. Without limits, a Redis instance can exhaust host memory, causing OOM conditions for other workloads. CPU limits prevent noisy neighbor effects.

#### Impact
Requires capacity planning to size limits appropriately for the expected working set.

#### Audit
```bash
docker inspect <container> | jq '.[0].HostConfig.Memory, .[0].HostConfig.NanoCpus'
# Expected: non-zero values

kubectl get pod <pod> -o jsonpath='{.spec.containers[*].resources}'
```

#### Remediation
```yaml
# Docker Compose
mem_limit: 2g
cpus: "1.0"

# Kubernetes
resources:
  limits:
    memory: "2Gi"
    cpu: "1000m"
  requests:
    memory: "512Mi"
    cpu: "250m"
```

Also configure `maxmemory` in Redis itself:
```
maxmemory 1800mb
maxmemory-policy allkeys-lru
```

#### Default Value
No resource limits are set by default.

#### References
- CIS Docker Benchmark
- NIST SP 800-53 Rev 5: SC-6, SI-17

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

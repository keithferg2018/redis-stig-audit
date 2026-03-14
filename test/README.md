# redis-stig-audit test plan

Planned fixtures:
- hardened Redis container
- vulnerable Redis container
- baseline Redis container

Planned validation:
- auth enabled vs disabled
- dangerous commands renamed/disabled
- protected mode on/off
- persistence and logging settings
- container hardening checks (non-root, read-only rootfs, caps drop)

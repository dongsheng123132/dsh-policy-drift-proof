# Security

Report vulnerabilities privately through GitHub Security Advisories for this repository.

The verifier is intentionally read-only with respect to policy state. It accepts only explicit workspace-relative manifest and snapshot paths, rejects symlinks and path escape, limits input size and structure, refuses secret-shaped fields, never emits policy values, performs no network requests or child processes, and writes only to an explicit workspace-relative artifact directory. A report proves only the supplied, pinned snapshots under the declared rules; it is not a policy enforcement engine or a security certification.

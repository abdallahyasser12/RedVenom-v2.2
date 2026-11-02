# Verifying a RedVenom run

Each completed run includes a `run_manifest.json` with relative artifact paths, byte sizes, and SHA-256 digests. The manifest can be checked offline:

```bash
python3 scripts/verify_run_manifest.py --run-dir recon_venom/runs/<run-id>
```

Exit codes are:

- `0`: every listed artifact exists and matches its recorded size and SHA-256 digest.
- `1`: one or more artifacts are missing, changed, duplicated, or unsafe to resolve.
- `2`: the manifest cannot be read or is not valid JSON.

The verifier rejects absolute paths, parent-directory traversal, symbolic links, duplicate paths, malformed digests, and unsupported schema versions. It reads files only and does not contact the target or an external service.

**Integrity is not truth.** A matching hash shows that a file is byte-for-byte consistent with the manifest. It does not establish that a scanner observation is exploitable, that the manifest itself is authentic, or that a target is secure. Keep the manifest and run directory private; an attacker able to replace both can also replace the recorded hashes.

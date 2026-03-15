# SARIF output schema reference

The `--sarif` flag produces a **SARIF 2.1.0** document.

External schema:
```
https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0-rtm.5.json
```

## Key mapping

| Audit field | SARIF field |
|---|---|
| `check_id` | `runs[].tool.driver.rules[].id` and `results[].ruleId` |
| `title` | `rules[].shortDescription.text` |
| `description` | `rules[].fullDescription.text` |
| `remediation` | `rules[].help.text` / `results[].fixes[].description.text` |
| `references[0]` | `rules[].helpUri` |
| `nist_800_53_controls` | `rules[].properties.tags` |
| `fedramp_control` | `rules[].properties.tags` (prefix `FedRAMP:`) |
| `benchmark_control_id` | `rules[].properties.tags` (prefix `benchmark:`) |
| `severity` | `rules[].defaultConfiguration.level` (CRITICAL/HIGH→error, MEDIUM→warning, LOW/INFO→note) |
| `status` | `results[].level` (FAIL/ERROR→error, WARN→warning, PASS/SKIP→none) |
| `actual` / `expected` | `results[].message.text` |
| `evidence[0].source` | `results[].locations[].logicalLocations[].name` |

## Artifact URI convention

Since redis-stig-audit is a runtime scanner (not a static code scanner), there
is no source file path. Artifact URIs use the `redis://` scheme with the target
display name, e.g. `redis://my-container` or `redis://127.0.0.1:6379`.

The `uriBaseId` is set to `REDIS_TARGET` with a human-readable description in
`originalUriBaseIds`.

## GitHub Code Scanning upload

```yaml
- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
    category: redis-stig-audit
```

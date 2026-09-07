# Fixture provenance

The VCEK certificate chains (`vcek-chain-*.pem`) and attestation reports
(`report_*.b64`) in this directory are copied from
[`yaxitech/routex-client-lua`](https://github.com/yaxitech/routex-client-lua),
`tests/data/` and `tests/attestation_spec.lua`, which is MIT licensed.

They are real AMD SEV-SNP data: complete `SEV-VCEK` -> `SEV-<gen>` -> `ARK-<gen>`
chains and the attestation reports that were signed under those leaves. That
makes the attestation path testable offline, end to end, against production
material rather than against a mock.

`report_genoa_v5` is expected to verify. The other three are expected to be
rejected for unmet platform requirements -- they are what proves the gates in
`Routex::ReportVerifier` actually fire.

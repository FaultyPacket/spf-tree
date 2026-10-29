# Security policy

Please report a vulnerability in this tool privately through
[GitHub private vulnerability reporting](https://github.com/FaultyPacket/spf-tree/security/advisories/new),
not as a public issue. Include the version, steps to reproduce and impact.

Supported: the latest 1.x release.

Scope: this repository's code and workflows. Findings the tool reports about
third-party domains are not vulnerabilities in this project.

The tool only makes read-only DNS and HTTPS requests (and port-25 probes with
`--smtp`). It sends nothing to FaultyPacket.

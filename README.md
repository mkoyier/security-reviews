# Web3 Security Research Portfolio

A collection of smart contract security audits, vulnerability research, and proof-of-concept exploits.

## Structure

```
web3-security-portfolio/
├── audit-reports/          # Full PDF/MD audit reports per project
│   └── [protocol-name]/
│       ├── AUDIT-REPORT.md
│       └── findings/
├── findings/               # Individual vulnerability write-ups
│   └── [VULN-ID]-[name].md
├── poc-exploits/           # Proof of concept exploit contracts
│   └── [protocol-name]/
│       ├── contracts/
│       ├── test/
│       └── README.md
├── tools/                  # Custom scripts and analysis tools
└── docs/
    ├── methodology.md
    └── severity-guide.md
```

## Audited Protocols

| Protocol | Type | Findings | Report |
|----------|------|----------|--------|
| DVWD - ABI Smuggling | Access Control | 1 Critical | [View](./audit-reports/dvwd-abi-smuggling/) |

## Vulnerability Classes Researched

- ABI/Calldata manipulation
- Reentrancy
- Flash loan attacks
- Access control bypass
- Oracle manipulation

## Methodology

See [docs/methodology.md](./docs/methodology.md) for my full audit process.

---

> All research is conducted on test environments and intentionally vulnerable codebases for educational purposes.

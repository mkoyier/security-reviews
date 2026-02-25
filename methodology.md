# Audit Methodology

## Phase 1 — Scoping

- Define contracts in scope
- Note any out-of-scope dependencies
- Identify protocol type (AMM, lending, vault, bridge, etc.)
- Record Solidity version and external libraries used

## Phase 2 — Reconnaissance

- Read all documentation and whitepapers
- Map contract architecture and interaction flows
- Identify privileged roles and admin functions
- List all entry points (external/public functions)

## Phase 3 — Static Analysis

Run automated tools first, then do manual review.

**Tools:**
- Slither: `slither . --print human-summary`
- Mythril: `myth analyze contracts/Target.sol`
- Remix IDE: Built-in static analysis tab

**Manual checklist:**
- [ ] Checks-effects-interactions pattern followed?
- [ ] All external calls handled safely?
- [ ] Access control on every privileged function?
- [ ] No use of `tx.origin` for auth?
- [ ] Integer math safe (Solidity ≥0.8 or SafeMath)?
- [ ] Reentrancy guards on state-changing functions?
- [ ] Oracle price feeds manipulation resistant?
- [ ] No hardcoded offsets in calldata parsing?
- [ ] Events emitted on all state changes?

## Phase 4 — Dynamic Analysis & PoC

- Deploy to local hardhat / foundry fork
- Write exploit contracts for each finding
- Confirm exploitability with passing test
- Measure financial impact where applicable

## Phase 5 — Reporting

- Write finding for each issue using [finding template](../findings/TEMPLATE.md)
- Assign severity using [severity guide](./severity-guide.md)
- Include remediation recommendation and patched code snippet
- Compile into full audit report using [audit template](../audit-reports/TEMPLATE.md)

## Phase 6 — Remediation Review (Optional)

- Review patched code after protocol team fixes
- Re-run PoC to confirm fix
- Note any residual risk

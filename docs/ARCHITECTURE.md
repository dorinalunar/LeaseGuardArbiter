# LeaseGuardArbiter Architecture & State Machine

## Lifecycle States
- `CREATED` -> `FUNDED` -> `EVIDENCE` -> `FROZEN` -> `PROVISIONAL_VERDICT` -> `SETTLED` -> `CLOSED`
- Alternate terminal/branch states: `CANCELLED`, `EXPIRED`, `APPEALING`

## Accounting Invariant
At all times, native contract balance satisfies:
`contract.balance >= escrowed_wei + staked_bonds_wei + total_claimable_wei + total_inflight_wei`

Only surplus above these four liability buckets can be swept by `admin` via `sweep_unallocated_balance()`.

## Consensus & Prompt Hardening
- Untrusted user strings (lease text, clauses, messages) are Unicode NFC-normalized, control-character stripped, bounded in length, and wrapped in `§BEGIN_EVIDENCE§ ... §END_EVIDENCE§` delimiters.
- Every remote image or invoice URL is fetched inside validator consensus and checked against its committed SHA-256 digest before LLM evaluation.

# LeaseGuardArbiter

**AI-adjudicated residential tenancy deposit escrow and multi-modal evidence arbitration Intelligent Contract on GenLayer.**

`LeaseGuardArbiter` locks residential security deposits on-chain and resolves end-of-tenancy deduction disputes through validator consensus (`gl.eq_principle.strict_eq`) across structured lease clauses, SHA-256-verified move-in / move-out photo pairs, repair invoices, and landlord-tenant correspondence.

## Architecture & Lifecycle

1. **Dispute Registration & Escrow Funding (`open_dispute`, `fund_escrow_landlord`, `fund_escrow_party`)**
   - Creates a dispute record with explicit tenancy timestamps, property reference, funding mode (`TENANCY_START` or `DISPUTE_TIME`), and exact deposit escrow amount (`>= 0.001 ETH / GEN`).
2. **Multi-Modal Evidence Submission (`attach_lease_agreement`, `attach_photo_evidence`, `attach_correspondence`, `attach_repair_invoices`, `file_deduction_schedule`)**
   - Binds lease text + structured clauses, paired move-in/move-out photo URLs + SHA-256 digests, message excerpts, and itemized landlord deduction claims.
   - Tracks landlord evidence epochs (`_landlord_evidence_epoch`) so tenant counter-evidence stays synchronized against the active landlord submission.
3. **Cryptographic Evidence Freeze (`lock_evidence_record`)**
   - After the 24-hour challenge window closes, computes a canonical SHA-256 snapshot across all claims, invoices, and active evidence slots.
4. **Two-Stage AI Jury Consensus (`evaluate_claim_item`, `issue_provisional_ruling`)**
   - **Stage 1:** Validators fetch and verify SHA-256 hashes of landlord move-in/move-out photos and optional repair receipts, then evaluate each deduction item against the lease clause and messages.
   - **Stage 2 (Tenant Counter-Photo Rebuttal):** When Stage 1 finds `TENANT_DAMAGE` and valid tenant counter-photos exist, a second consensus-bound jury stage checks whether tenant media proves `PRE_EXISTING` damage or contradicts the move-out damage claim.
5. **Amicable Settlement, Appeal & Pull-Based Payouts (`offer_amicable_split`, `accept_amicable_split`, `file_appeal`, `finalize_appeal_ruling`, `withdraw_entitlement`, `acknowledge_withdrawal`)**
   - Parties can settle amicably with zero protocol fee prior to evidence freeze, or the losing party can stake an appeal bond within 24 hours for blind re-adjudication.

## Repository Layout

```text
LeaseGuardArbiter/
├── .github/workflows/ci.yml      # Ruff lint + pytest CI pipeline
├── contracts/
│   └── LeaseGuardArbiter.py      # GenLayer Intelligent Contract (v0.3.0)
├── docs/
│   └── ARCHITECTURE.md           # State machine & consensus invariants
├── fixtures/
│   └── sample_dispute.json       # Sample clauses, photo hashes & claim payload
├── scripts/
│   └── verify_integrity.py       # Contract SHA-256 & syntax verification helper
├── tests/
│   └── test_lease_guard_arbiter.py
├── README.md
├── STUDIO_DEV_DEPLOY.md
├── pyproject.toml
└── requirements-dev.txt
```

## Quick Verification

```bash
pip install -r requirements-dev.txt
ruff check contracts/ tests/ scripts/
pytest -v
python scripts/verify_integrity.py
```

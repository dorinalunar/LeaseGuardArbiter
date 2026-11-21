import importlib.util
import json
import sys
import types
from pathlib import Path


def _load_contract_module():
    gl_mod = types.ModuleType("genlayer")
    storage_mod = types.ModuleType("genlayer.storage")
    types_mod = types.ModuleType("genlayer.types")

    class _UserError(Exception):
        pass

    class _TreeMap(dict):
        def __class_getitem__(cls, _item):
            return cls

    class _Contract:
        balance = 0

        def __init__(self):
            for name, ann in getattr(type(self), "__annotations__", {}).items():
                if ann is _TreeMap or getattr(ann, "__origin__", None) is _TreeMap:
                    setattr(self, name, _TreeMap())

    class _Public:
        @staticmethod
        def view(fn):
            return fn

        class _Write:
            def __call__(self, fn):
                return fn

            @staticmethod
            def payable(fn):
                return fn

        write = _Write()

    class _Evm:
        @staticmethod
        def contract_interface(cls):
            return cls

    gl_mod.vm = types.SimpleNamespace(UserError=_UserError)
    gl_mod.contract = types.SimpleNamespace(Contract=_Contract)
    gl_mod.public = _Public()
    gl_mod.evm = _Evm()
    gl_mod.message = types.SimpleNamespace(
        sender_address="0x" + "1" * 40,
        datetime="2026-11-21T12:00:00Z",
        value=0,
    )
    gl_mod.nondet = types.SimpleNamespace(
        web=types.SimpleNamespace(get=lambda _u: None),
        exec_prompt=lambda *_a, **_kw: {},
    )
    gl_mod.eq_principle = types.SimpleNamespace(strict_eq=lambda fn: fn())

    storage_mod.TreeMap = _TreeMap
    types_mod.Address = str
    types_mod.bigint = int
    types_mod.u256 = int

    sys.modules["genlayer"] = gl_mod
    sys.modules["genlayer.storage"] = storage_mod
    sys.modules["genlayer.types"] = types_mod

    contract_path = Path(__file__).resolve().parent.parent / "contracts" / "LeaseGuardArbiter.py"
    spec = importlib.util.spec_from_file_location("lease_guard_arbiter", contract_path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod, gl_mod


mod, gl = _load_contract_module()
ADMIN = "0x" + "1" * 40
LANDLORD = "0x" + "a" * 40
TENANT = "0x" + "b" * 40
DEPOSIT = str(mod.MIN_ESCROW_WEI * 10)


def _new_arbiter():
    arbiter = mod.LeaseGuardArbiter()
    arbiter.disputes = {}
    arbiter.payout_ledger = {}
    arbiter.inflight_payouts = {}
    arbiter.landlord_metrics = {}
    return arbiter


def _setup_funded_dispute():
    gl.message.sender_address = ADMIN
    gl.message.datetime = "2026-11-21T12:00:00Z"
    gl.message.value = 0
    arbiter = _new_arbiter()
    res = arbiter.open_dispute(
        LANDLORD,
        TENANT,
        "Apt 4B, 120 Oak Ave",
        DEPOSIT,
        "1790000000",
        "1800000000",
        "en",
        "DISPUTE_TIME",
    )
    assert res == "CASE #0 CREATED"

    gl.message.sender_address = LANDLORD
    gl.message.value = int(DEPOSIT)
    arbiter.balance = int(DEPOSIT)
    funded = arbiter.fund_escrow_landlord(0)
    assert funded.startswith("CASE_FUNDED:")
    gl.message.value = 0
    return arbiter


def test_protocol_stats_and_admin_nomination():
    gl.message.sender_address = ADMIN
    arbiter = _new_arbiter()
    stats = json.loads(arbiter.get_protocol_stats())
    assert stats["name"] == "LeaseGuardArbiter"
    assert stats["owner"] == ADMIN
    assert stats["paused"] is False

    arbiter.nominate_admin(LANDLORD)
    gl.message.sender_address = LANDLORD
    out = arbiter.accept_admin_role()
    assert "OWNERSHIP_TRANSFERRED" in out
    assert arbiter.admin == LANDLORD


def test_evidence_submission_freeze_and_ruling():
    arbiter = _setup_funded_dispute()
    gl.message.sender_address = LANDLORD

    clauses = json.dumps([{"clause_id": "CL-1", "text": "No burn damage to flooring."}])
    assert "LEASE_SUBMITTED" in arbiter.attach_lease_agreement(0, "Full lease agreement text.", clauses)

    photos = json.dumps(
        {
            "move_in": [{"url": "https://example.com/in.jpg", "sha256": "a" * 64}],
            "move_out": [{"url": "https://example.com/out.jpg", "sha256": "b" * 64}],
        }
    )
    assert "PHOTOS_SUBMITTED" in arbiter.attach_photo_evidence(0, photos)
    assert "MESSAGES_SUBMITTED" in arbiter.attach_correspondence(0, "Tenant acknowledged burn mark.")

    claims = json.dumps(
        [{"item": "Floor burn repair", "claimed_amount_wei": str(mod.MIN_ESCROW_WEI * 4), "clause_id": "CL-1"}]
    )
    assert "CLAIMS_SET" in arbiter.file_deduction_schedule(0, claims)

    gl.message.datetime = "2026-11-22T13:00:00Z"
    frozen = arbiter.lock_evidence_record(0)
    assert frozen.startswith("EVIDENCE_FROZEN:")

    state = json.loads(arbiter.get_dispute_state(0))
    state["cvs"]["claim_1"] = {
        "claim_id": "claim_1",
        "category": "TENANT_DAMAGE",
        "bucket_pct": 50,
        "reason_code": "CLAUSE_BREACH",
        "msg_support": "SUPPORTED",
        "photo_pair_id": "pair_1",
        "counter_verdict": "NONE",
    }
    arbiter.disputes["0"] = json.dumps(state)

    ruling = arbiter.issue_provisional_ruling(0)
    assert ruling.startswith("PROVISIONAL_VERDICT:")

    gl.message.datetime = "2026-11-23T14:00:00Z"
    settled = arbiter.finalize_escrow_distribution(0)
    assert settled.startswith("CASE_SETTLED:")


def test_amicable_settlement_zero_fee():
    arbiter = _setup_funded_dispute()
    half = str(int(DEPOSIT) // 2)

    gl.message.sender_address = LANDLORD
    assert "SETTLEMENT_PROPOSED" in arbiter.offer_amicable_split(0, half, half)

    gl.message.sender_address = TENANT
    assert "SETTLEMENT_ACCEPTED" in arbiter.accept_amicable_split(0)
    assert arbiter.get_claimable_balance(TENANT, 0) == half
    assert arbiter.get_claimable_balance(LANDLORD, 0) == half
    assert arbiter.get_claimable_balance(ADMIN, 0) == "0"


def test_verdict_validation_rules():
    assert mod._parse_primary_verdict(
        {
            "claim_id": "claim_1",
            "category": "WEAR_AND_TEAR",
            "bucket_pct": 25,
            "reason_code": "NORMAL_WEAR",
            "msg_support": "NONE",
            "photo_pair_id": "NONE",
        },
        "claim_1",
        "pair_1",
    ) is None

    valid = mod._parse_primary_verdict(
        {
            "claim_id": "claim_1",
            "category": "TENANT_DAMAGE",
            "bucket_pct": 75,
            "reason_code": "CLAUSE_BREACH",
            "msg_support": "SUPPORTED",
            "photo_pair_id": "pair_1",
        },
        "claim_1",
        "pair_1",
    )
    assert valid is not None and valid["bucket_pct"] == 75

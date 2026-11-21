import ast
import hashlib
from pathlib import Path

CONTRACT_PATH = Path(__file__).resolve().parent.parent / "contracts" / "LeaseGuardArbiter.py"


def main() -> None:
    raw = CONTRACT_PATH.read_bytes()
    ast.parse(raw.decode("utf-8"), filename=str(CONTRACT_PATH))
    digest = hashlib.sha256(raw).hexdigest()
    print(f"File: {CONTRACT_PATH.name}")
    print(f"Bytes: {len(raw)}")
    print(f"SHA-256: {digest}")


if __name__ == "__main__":
    main()

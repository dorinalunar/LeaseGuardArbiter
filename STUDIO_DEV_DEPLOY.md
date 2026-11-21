# GenLayer Studio Dev Deployment Guide (Chain ID 61997)

## Target Network
- **Environment:** GenLayer Studio Dev
- **Chain ID:** `61997` (`0xf22d`)
- **Studio URL:** `https://studio-dev.genlayer.com`
- **Explorer URL:** `https://explorer-studio-dev.genlayer.com`

## Deployment Steps
1. Open [GenLayer Studio Dev](https://studio-dev.genlayer.com) and connect your deployer wallet.
2. Upload `contracts/LeaseGuardArbiter.py`.
3. Verify the dependency header matches:
   `# { "Depends": "py-genlayer:babwp9t37jw9g4j2bccgn14g6x7x9s1f7dsmh7emvz735pz4zxa0" }`
4. Deploy `LeaseGuardArbiter` (constructor takes no arguments and assigns `admin` to `gl.message.sender_address`).
5. Confirm deployment via read call `get_protocol_stats()` and verify the `name` field returns `"LeaseGuardArbiter"`.
6. Record the deployed contract address, deployment transaction hash, and output of `python scripts/verify_integrity.py` for milestone submission.

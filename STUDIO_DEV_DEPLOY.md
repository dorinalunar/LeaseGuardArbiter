# GenLayer Studio Dev Deployment (Chain ID 61997)

## Live Deployment
- **Network:** GenLayer Studio Dev (`Chain ID: 61997` / `0xf22d`)
- **Contract Address:** `0xbbbDdA97367cfd1d518404553935466ad7D57faC`
- **Studio Import:** https://studio-dev.genlayer.com/?import-contract=0xbbbDdA97367cfd1d518404553935466ad7D57faC
- **Explorer:** https://explorer-studio-dev.genlayer.com/address/0xbbbDdA97367cfd1d518404553935466ad7D57faC
- **Contract File:** `contracts/LeaseGuardArbiter.py`
- **SHA-256:** `a01a14a2ecfd195b1ab7fee4efa6c2a7c3c0136bcce889cf8444460521db9664`

## Deployment Notes
1. `contracts/LeaseGuardArbiter.py` starts directly with the dependency directive:
   `# { "Depends": "py-genlayer:babwp9t37jw9g4j2bccgn14g6x7x9s1f7dsmh7emvz735pz4zxa0" }`
2. Constructor takes no parameters and assigns `admin` to the deployer address.
3. Verify protocol state via read call `get_protocol_stats()`.

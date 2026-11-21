# GenLayer Studio Dev Deployment (Chain ID 61997)

## Live Deployment
- **Network:** GenLayer Studio Dev (`Chain ID: 61997` / `0xf22d`)
- **Contract Address:** `0xD7CdBE4d8b35355cc6f82D8fFF3b9fF7a3092AcB`
- **Studio Import:** https://studio-dev.genlayer.com/?import-contract=0xD7CdBE4d8b35355cc6f82D8fFF3b9fF7a3092AcB
- **Explorer:** https://explorer-studio-dev.genlayer.com/address/0xD7CdBE4d8b35355cc6f82D8fFF3b9fF7a3092AcB
- **Contract File:** `contracts/LeaseGuardArbiter.py`
- **SHA-256:** `e5cd3baf9aa27e55b112b6ae65d6fc2bf95e06e161e5814eab6733a2d60d997f`

## Deployment Notes
1. `contracts/LeaseGuardArbiter.py` starts directly with the dependency directive:
   `# { "Depends": "py-genlayer:1jb45aa8ynh2a9c9xn3b7qqh8sm5q93hwfp7jqmwsfhh8jpz09h6" }`
2. Constructor takes no parameters and assigns `admin` to the deployer address.
3. Verify protocol state via read call `get_protocol_stats()`.

# ADOS22

This directory contains the ADOS22 homomorphic secret sharing implementation as a standalone subproject.

## Scope

- Public API: `include/ados22/ados22.hpp`
- Protocol core: `src/core.*`
- ElGamal primitive layer: `src/elgamal.*`
- Local support utilities: `src/support.hpp`
- Demo program: `demo/main.cpp`

The refactor preserves the original algorithmic flow, but the bottom layer is no longer a thin compatibility wrapper. The protocol logic now lives in `src/core.*`, while the ElGamal-based primitive operations live in `src/elgamal.*`.

## Build

```bash
cmake -S . -B build
cmake --build build -j
```

If NTL is not installed in a default location:

```bash
cmake -S . -B build -DNTL_DIR=/path/to/ntl
cmake --build build -j
```

## Run the Demo

```bash
./build/ados22_demo
```

The demo prints the protocol name and reconstructs `45 * 45 + 1`, which yields `2026`.

## Public API Shape

The public API exposes these functions:

- `ados22::KeyGen`
- `ados22::ShareInput`
- `ados22::ConvertInput`
- `ados22::EvalAdd`
- `ados22::EvalMul`
- `ados22::Reconstruct`

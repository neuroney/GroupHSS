# OSY21

This directory contains the OSY21 homomorphic secret sharing implementation as a standalone subproject.

## Scope

- Public API: `include/osy21/osy21.hpp`
- Protocol core: `src/core.*`
- Paillier primitive layer: `src/paillier.*`
- Demo program: `demo/main.cpp`

The original implementation was a single header containing both protocol logic and primitive code. It is now split into a protocol core layer and a Paillier primitive layer, with unused `PaillierEG_*` code removed.

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
./build/osy21_demo
```

The demo prints the protocol name and reconstructs `45 * 45 + 1`, which yields `2026`.

## Public API Shape

The public API exposes these functions:

- `osy21::KeyGen`
- `osy21::ShareInput`
- `osy21::ConvertInput`
- `osy21::EvalAdd`
- `osy21::EvalMul`
- `osy21::Reconstruct`

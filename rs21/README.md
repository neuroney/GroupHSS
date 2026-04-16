# RS21

This directory contains the RS21 homomorphic secret sharing implementation as a standalone subproject.

## Scope

- Public API: `include/rs21/rs21.hpp`
- Protocol core: `src/core.*`
- Damgard-Jurik primitive layer: `src/dj.*`
- Local support utilities: `src/support.hpp`
- Demo program: `demo/main.cpp`

The refactor preserves the original protocol logic, but the internal layout now matches the other subprojects: a protocol core layer on top of a dedicated primitive layer.

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
./build/rs21_demo
```

The demo prints the protocol name and reconstructs `45 * 45 + 1`, which yields `2026`.

## Public API Shape

The public API exposes these functions:

- `rs21::KeyGen`
- `rs21::ShareInput`
- `rs21::ConvertInput`
- `rs21::EvalAdd`
- `rs21::EvalMul`
- `rs21::Reconstruct`

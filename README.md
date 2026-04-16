# GroupHSS

GroupHSS provides a C++17 implementation of three Group-based homomorphic secret sharing (HSS) based on [OSY21, RS21, ADOS22], that allows us to build secure two-party computation protocols.

[OSY21]: Claudio Orlandi, Peter Scholl, and Sophia Yakoubov.  
*The Rise of Paillier: Homomorphic Secret Sharing and Public-Key Silent OT*.  
In *EUROCRYPT 2021*.  
DOI: https://doi.org/10.1007/978-3-030-77870-5_24  

[RS21]: Lawrence Roy and Jaspal Singh.  
*Large Message Homomorphic Secret Sharing from DCR and Applications*.  
In *CRYPTO 2021*.  
DOI: https://doi.org/10.1007/978-3-030-84252-9_23  

[ADOS22]: Damiano Abram, Ivan Damgård, Claudio Orlandi, and Peter Scholl.  
*An Algebraic Framework for Silent Preprocessing with Trustless Setup and Active Security*.  
In *CRYPTO 2022*.  
DOI: https://doi.org/10.1007/978-3-031-15985-5_15  

This repository is **not** for production use; it is not extensively tested.

The repository is organized as **three standalone subprojects**.  
Each protocol keeps its own source tree, build configuration, demo, and smoke test, so it can be copied, built, and studied independently.

## Included Protocol Lines

| Directory | Tag | Paper / protocol line | 
| --- | --- | --- | 
| `osy21/` | OSY21 | Paillier-based HSS | 
| `rs21/` | RS21 | DCR / Damgård–Jurik-based HSS | 
| `ados22/` | ADOS22 | Elgamal-based HSS | 

## Quick Start

Build one protocol from its own directory:

```bash
cmake -S osy21 -B build-osy21
cmake --build build-osy21 -j
./build-osy21/osy21_demo
ctest --test-dir build-osy21 --output-on-failure
```

Equivalent commands work for rs21 and ados22.

## Dependencies

- C++17 compiler
- CMake 3.16 or newer
- [NTL](https://libntl.org/)
- [GMP](https://gmplib.org/)

If CMake cannot find NTL automatically, pass `-DNTL_DIR=/path/to/ntl` when configuring a subproject.

## Verified Build Environment

The current repository state was verified with:

- GCC 11.4.0
- CMake 3.16+
- NTL 11.5.1
- GMP 6.2.1

## Acknowledgments

- Thanks to [Y-Liu0722](https://github.com/Y-Liu0722) for implementing RS21.

## License

Unless explicitly stated otherwise, this repository is released under the MIT License. See [LICENSE](LICENSE).
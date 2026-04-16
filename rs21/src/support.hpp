#pragma once

#include <NTL/ZZ.h>
#include <NTL/vector.h>

#include <array>
#include <cstdint>
#include <vector>

using namespace std;
using namespace NTL;

inline void LCM(ZZ &result, const ZZ &lhs, const ZZ &rhs)
{
    ZZ gcd;
    GCD(gcd, lhs, rhs);
    result = (lhs / gcd) * rhs;
}

inline constexpr long kPrimeBits = 1536;

inline void GenerateGermainPrimePair(ZZ &p, ZZ &q, long bits = kPrimeBits)
{
    GenGermainPrime(p, bits);

    do
    {
        GenGermainPrime(q, bits);
    } while (q == p);
}

inline ZZ PRF_ZZ(long key, const ZZ &modulus)
{
    if (sign(modulus) <= 0)
    {
        return ZZ(0);
    }

    std::array<unsigned char, NTL_PRG_KEYLEN> prg_key{};
    std::array<unsigned char, sizeof(std::uint64_t)> seed_material{};
    const std::uint64_t state =
        static_cast<std::uint64_t>(static_cast<std::uint32_t>(key));

    for (long index = 0; index < static_cast<long>(seed_material.size()); ++index)
    {
        seed_material[index] =
            static_cast<unsigned char>((state >> (8 * index)) & 0xffU);
    }

    DeriveKey(
        prg_key.data(),
        NTL_PRG_KEYLEN,
        seed_material.data(),
        static_cast<long>(seed_material.size()));

    RandomStreamPush random_scope;
    RandomStream random_stream(prg_key.data());
    SetSeed(random_stream);

    ZZ value;
    RandomBnd(value, modulus);
    return value;
}

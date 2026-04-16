#pragma once

#include <NTL/ZZ.h>
#include <NTL/vector.h>

#include <array>
#include <cstdint>
#include <vector>

namespace osy21::detail
{
inline constexpr long kPrimeBits = 1536;

inline void GenerateGermainPrimePair(NTL::ZZ &p, NTL::ZZ &q, long bits = kPrimeBits)
{
    NTL::GenGermainPrime(p, bits);

    do
    {
        NTL::GenGermainPrime(q, bits);
    } while (q == p);
}

inline NTL::ZZ PRF_ZZ(long key, const NTL::ZZ &modulus)
{
    if (NTL::sign(modulus) <= 0)
    {
        return NTL::ZZ(0);
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

    NTL::DeriveKey(
        prg_key.data(),
        NTL_PRG_KEYLEN,
        seed_material.data(),
        static_cast<long>(seed_material.size()));

    NTL::RandomStreamPush random_scope;
    NTL::RandomStream random_stream(prg_key.data());
    NTL::SetSeed(random_stream);

    NTL::ZZ value;
    NTL::RandomBnd(value, modulus);
    return value;
}
} // namespace osy21::detail

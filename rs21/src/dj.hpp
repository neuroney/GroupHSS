#pragma once

#include "support.hpp"

namespace rs21::detail
{
struct DjPublicKey
{
    int s;
    ZZ modulus;
    ZZ modulus_power_s;
    ZZ modulus_power_s_plus_1;
};

void GenerateDjKeys(DjPublicKey &public_key, ZZ &secret_key, int s);
void EncryptDj(ZZ &ciphertext, const DjPublicKey &public_key, const ZZ &message);
void DecryptDj(ZZ &message, const DjPublicKey &public_key, const ZZ &secret_key, const ZZ &ciphertext);
void Distinguish(ZZ &result, const DjPublicKey &public_key, const ZZ &value);
void Exponentiate(ZZ &result, const DjPublicKey &public_key, const ZZ &value);
void Logarithm(ZZ &result, const DjPublicKey &public_key, const ZZ &value);
} // namespace rs21::detail

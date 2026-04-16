#pragma once

#include "support.hpp"

namespace ados22::detail
{
struct PublicKey
{
    ZZ f;
    ZZ g;
    ZZ h;
    ZZ modulus;
    ZZ modulus_square;
};

using SecretKey = ZZ;
using PrimitiveCiphertext = array<ZZ, 2>;

void GenerateElgamalKeys(PublicKey &public_key, SecretKey &secret_key, int secret_key_bits);
void Encrypt(PrimitiveCiphertext &ciphertext, const PublicKey &public_key, const ZZ &message);
void EncryptWithEmbeddedSecret(
    PrimitiveCiphertext &ciphertext,
    const PublicKey &public_key,
    const ZZ &message);
void Decrypt(
    ZZ &message,
    const PublicKey &public_key,
    const SecretKey &secret_key,
    const PrimitiveCiphertext &ciphertext);
} // namespace ados22::detail

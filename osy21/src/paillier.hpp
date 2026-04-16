#pragma once

#include "support.hpp"

namespace osy21::detail
{
struct PublicKey
{
    int digit_count = 0;
    NTL::ZZ modulus_square;
    int security_parameter = 683;
    NTL::ZZ message_bound;
    NTL::ZZ secret_key_base;

    NTL::ZZ modulus;
    NTL::Vec<NTL::ZZ> encrypted_secret_digits;
    NTL::ZZ decryption_key;
    NTL::Vec<NTL::ZZ> secret_key_digits;
};

void GeneratePaillierKeys(PublicKey &public_key, NTL::ZZ &secret_key);
void EncryptPaillier(NTL::ZZ &ciphertext, const PublicKey &public_key, const NTL::ZZ &message);
void DecryptPaillier(NTL::ZZ &message, const PublicKey &public_key, const NTL::ZZ &ciphertext);
} // namespace osy21::detail

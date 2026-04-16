#include "paillier.hpp"

namespace osy21::detail
{
void GeneratePaillierKeys(PublicKey &public_key, NTL::ZZ &secret_key)
{
    NTL::ZZ p;
    NTL::ZZ q;
    NTL::ZZ phi_n;
    NTL::ZZ temporary1;
    NTL::ZZ temporary2;

    GenerateGermainPrimePair(p, q);
    mul(public_key.modulus, p, q);
    mul(public_key.modulus_square, public_key.modulus, public_key.modulus);

    temporary1 = p - 1;
    temporary2 = q - 1;
    mul(phi_n, temporary1, temporary2);
    InvMod(temporary1, phi_n, public_key.modulus);
    mul(temporary1, temporary1, phi_n);
    mul(temporary2, public_key.modulus, phi_n);
    rem(secret_key, temporary1, temporary2);
    public_key.decryption_key = secret_key;

    power(public_key.message_bound, 2, public_key.security_parameter);
    power(public_key.secret_key_base, 2, public_key.security_parameter);
}

void EncryptPaillier(
    NTL::ZZ &ciphertext,
    const PublicKey &public_key,
    const NTL::ZZ &message)
{
    NTL::ZZ randomness;
    NTL::ZZ random_term;
    NTL::ZZ message_term = public_key.modulus + 1;

    RandomBnd(randomness, public_key.modulus_square);
    PowerMod(random_term, randomness, public_key.modulus, public_key.modulus_square);
    PowerMod(message_term, message_term, message, public_key.modulus_square);
    MulMod(ciphertext, random_term, message_term, public_key.modulus_square);
}

void DecryptPaillier(
    NTL::ZZ &message,
    const PublicKey &public_key,
    const NTL::ZZ &ciphertext)
{
    NTL::ZZ temporary;
    PowerMod(
        temporary,
        ciphertext,
        public_key.decryption_key,
        public_key.modulus_square);
    message = (temporary - 1) / public_key.modulus;
}
} // namespace osy21::detail

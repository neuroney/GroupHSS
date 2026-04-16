#include "elgamal.hpp"

namespace ados22::detail
{
void GenerateElgamalKeys(PublicKey &public_key, SecretKey &secret_key, int secret_key_bits)
{
    ZZ p;
    ZZ q;
    GenerateGermainPrimePair(p, q);

    mul(public_key.modulus, p, q);
    mul(public_key.modulus_square, public_key.modulus, public_key.modulus);

    RandomBnd(public_key.g, public_key.modulus_square);
    while (Jacobi(public_key.g, public_key.modulus) != 1)
    {
        RandomBnd(public_key.g, public_key.modulus_square);
    }

    add(public_key.f, public_key.modulus, 1);

    RandomBits(secret_key, secret_key_bits);
    PowerMod(public_key.h, public_key.g, secret_key, public_key.modulus_square);
}

void Encrypt(PrimitiveCiphertext &ciphertext, const PublicKey &public_key, const ZZ &message)
{
    ZZ randomness;
    RandomBnd(randomness, public_key.modulus);

    PowerMod(ciphertext[0], public_key.g, randomness, public_key.modulus_square);
    PowerMod(ciphertext[1], public_key.h, randomness, public_key.modulus_square);
    MulMod(
        ciphertext[1],
        ciphertext[1],
        1 + public_key.modulus * message,
        public_key.modulus_square);
}

void EncryptWithEmbeddedSecret(
    PrimitiveCiphertext &ciphertext,
    const PublicKey &public_key,
    const ZZ &message)
{
    ZZ randomness;
    RandomBnd(randomness, public_key.modulus);

    PowerMod(ciphertext[0], public_key.g, randomness, public_key.modulus_square);
    MulMod(
        ciphertext[0],
        ciphertext[0],
        1 - public_key.modulus * message,
        public_key.modulus_square);
    PowerMod(ciphertext[1], public_key.h, randomness, public_key.modulus_square);
}

void Decrypt(
    ZZ &message,
    const PublicKey &public_key,
    const SecretKey &secret_key,
    const PrimitiveCiphertext &ciphertext)
{
    ZZ temporary;
    PowerMod(temporary, ciphertext[0], -secret_key, public_key.modulus_square);
    MulMod(temporary, ciphertext[1], temporary, public_key.modulus_square);

    sub(temporary, temporary, 1);
    div(message, temporary, public_key.modulus);
}
} // namespace ados22::detail

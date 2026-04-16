#include "dj.hpp"

namespace rs21::detail
{
void GenerateDjKeys(DjPublicKey &public_key, ZZ &secret_key, int s)
{
    ZZ p;
    ZZ q;

    public_key.s = s;
    GenerateGermainPrimePair(p, q);
    mul(public_key.modulus, p, q);
    power(public_key.modulus_power_s, public_key.modulus, public_key.s);
    mul(
        public_key.modulus_power_s_plus_1,
        public_key.modulus_power_s,
        public_key.modulus);
    LCM(secret_key, p - 1, q - 1);
}

void EncryptDj(ZZ &ciphertext, const DjPublicKey &public_key, const ZZ &message)
{
    ZZ randomness;
    ZZ random_term;
    ZZ message_term;

    RandomBnd(randomness, public_key.modulus_power_s_plus_1);
    PowerMod(
        random_term,
        randomness,
        public_key.modulus_power_s,
        public_key.modulus_power_s_plus_1);
    Exponentiate(message_term, public_key, message);
    MulMod(
        ciphertext,
        random_term,
        message_term,
        public_key.modulus_power_s_plus_1);
}

void DecryptDj(
    ZZ &message,
    const DjPublicKey &public_key,
    const ZZ &secret_key,
    const ZZ &ciphertext)
{
    ZZ temporary;
    ZZ inverse_secret_key;

    PowerMod(
        temporary,
        ciphertext,
        secret_key,
        public_key.modulus_power_s_plus_1);
    Logarithm(temporary, public_key, temporary);
    InvMod(inverse_secret_key, secret_key, public_key.modulus_power_s_plus_1);
    MulMod(message, temporary, inverse_secret_key, public_key.modulus_power_s);
}

void Exponentiate(ZZ &result, const DjPublicKey &public_key, const ZZ &value)
{
    ZZ nx;
    MulMod(nx, public_key.modulus, value, public_key.modulus_power_s_plus_1);
    AddMod(result, ZZ(1), nx, public_key.modulus_power_s_plus_1);

    ZZ term = nx;
    ZZ inverse_index;
    for (int index = 2; index <= public_key.s; ++index)
    {
        MulMod(term, term, nx, public_key.modulus_power_s_plus_1);
        InvMod(inverse_index, ZZ(index), public_key.modulus_power_s_plus_1);
        MulMod(term, term, inverse_index, public_key.modulus_power_s_plus_1);
        AddMod(result, result, term, public_key.modulus_power_s_plus_1);
    }
}

void Logarithm(ZZ &result, const DjPublicKey &public_key, const ZZ &value)
{
    ZZ quotient;
    div(quotient, value - 1, public_key.modulus);
    result = quotient;

    ZZ term = quotient;
    ZZ negative_nx;
    ZZ inverse_index;
    MulMod(
        negative_nx,
        public_key.modulus,
        -quotient,
        public_key.modulus_power_s);

    for (int index = 2; index <= public_key.s; ++index)
    {
        MulMod(term, term, negative_nx, public_key.modulus_power_s);
        InvMod(inverse_index, ZZ(index), public_key.modulus_power_s_plus_1);
        MulMod(term, term, inverse_index, public_key.modulus_power_s);
        AddMod(result, result, term, public_key.modulus_power_s);
        MulMod(term, term, ZZ(index), public_key.modulus_power_s);
    }
}

void Distinguish(ZZ &result, const DjPublicKey &public_key, const ZZ &value)
{
    ZZ reduced;
    ZZ inverse_reduced;
    ZZ normalized;

    rem(reduced, value, public_key.modulus);
    InvMod(inverse_reduced, reduced, public_key.modulus_power_s_plus_1);
    MulMod(
        normalized,
        value,
        inverse_reduced,
        public_key.modulus_power_s_plus_1);
    Logarithm(result, public_key, normalized);
}
} // namespace rs21::detail

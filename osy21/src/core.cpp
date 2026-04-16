#include "core.hpp"

namespace
{
void EnsureShareLength(osy21::detail::Share &share, long length)
{
    if (share.length() != length)
    {
        share.SetLength(length);
    }
}

NTL::ZZ ExtractDiscreteDifferenceLog(
    const osy21::detail::PublicKey &public_key,
    const NTL::ZZ &value)
{
    NTL::ZZ quotient;
    NTL::ZZ remainder;
    NTL::ZZ inverse;
    NTL::ZZ result;

    DivRem(quotient, remainder, value, public_key.modulus);
    inverse = InvMod(remainder, public_key.modulus);
    MulMod(result, quotient, inverse, public_key.modulus);
    return result;
}
} // namespace

namespace osy21::detail
{
void GenerateKeys(PublicKey &public_key, EvaluationKey &eval_key0, EvaluationKey &eval_key1)
{
    NTL::ZZ secret_key;
    GeneratePaillierKeys(public_key, secret_key);

    NTL::ZZ remaining = secret_key;
    NTL::ZZ digit;
    while (remaining != 0)
    {
        DivRem(remaining, digit, remaining, public_key.secret_key_base);
        public_key.secret_key_digits.append(digit);
    }
    public_key.digit_count = public_key.secret_key_digits.length();

    const NTL::ZZ bound = public_key.message_bound * public_key.secret_key_base;
    public_key.encrypted_secret_digits.SetLength(public_key.digit_count);
    for (int index = 0; index < public_key.digit_count; ++index)
    {
        RandomBnd(digit, bound);
        eval_key1.masked_secret_digits.append(digit);
        eval_key0.masked_secret_digits.append(digit - public_key.secret_key_digits[index]);
        EncryptPaillier(
            public_key.encrypted_secret_digits[index],
            public_key,
            public_key.secret_key_digits[index]);
    }
}

void EncryptInput(Ciphertext &ciphertext, const PublicKey &public_key, const NTL::ZZ &message)
{
    ciphertext.SetLength(0);

    NTL::ZZ head_ciphertext;
    EncryptPaillier(head_ciphertext, public_key, message);
    ciphertext.append(head_ciphertext);

    for (int index = 0; index < public_key.digit_count; ++index)
    {
        NTL::ZZ randomness;
        NTL::ZZ random_term;
        NTL::ZZ message_term;
        NTL::ZZ component;

        RandomBnd(randomness, public_key.modulus_square);
        random_term = PowerMod(randomness, public_key.modulus, public_key.modulus_square);
        message_term = PowerMod(
            public_key.encrypted_secret_digits[index],
            message,
            public_key.modulus_square);
        component = MulMod(random_term, message_term, public_key.modulus_square);
        ciphertext.append(component);
    }
}

void ConvertInput(
    Share &share,
    int party,
    const PublicKey &public_key,
    const EvaluationKey &eval_key,
    const Ciphertext &ciphertext,
    int &prf_state)
{
    NTL::ZZ mask;
    RandomBnd(mask, public_key.message_bound);

    Share decomposition;
    if (party == 0)
    {
        decomposition.append(mask);
    }
    else
    {
        AddMod(mask, mask, NTL::ZZ(1), public_key.modulus);
        decomposition.append(mask);
    }
    decomposition.append(eval_key.masked_secret_digits);

    EnsureShareLength(share, public_key.digit_count + 1);
    MultiplyShare(share, party, public_key, eval_key, ciphertext, decomposition, prf_state);
}

void AddShares(
    Share &sum,
    int party,
    const PublicKey &public_key,
    const EvaluationKey &eval_key,
    const Share &lhs,
    const Share &rhs,
    int &prf_state)
{
    (void)party;
    (void)eval_key;

    EnsureShareLength(sum, public_key.digit_count + 1);
    for (int index = 0; index < public_key.digit_count + 1; ++index)
    {
        sum[index] = lhs[index] + rhs[index];
    }

    AddMod(sum[0], sum[0], PRF_ZZ(prf_state++, public_key.modulus), public_key.modulus);
}

void MultiplyShare(
    Share &product,
    int party,
    const PublicKey &public_key,
    const EvaluationKey &eval_key,
    const Ciphertext &ciphertext,
    const Share &share,
    int &prf_state)
{
    (void)party;
    (void)eval_key;

    EnsureShareLength(product, public_key.digit_count + 1);

    NTL::ZZ exponent(0);
    for (int index = 0; index < public_key.digit_count; ++index)
    {
        exponent += power(public_key.secret_key_base, index) * share[index + 1];
    }

    for (int index = 0; index < public_key.digit_count + 1; ++index)
    {
        NTL::ZZ temporary = PowerMod(
            ciphertext[index],
            exponent,
            public_key.modulus_square);
        product[index] = ExtractDiscreteDifferenceLog(public_key, temporary);
    }

    AddMod(
        product[0],
        product[0],
        PRF_ZZ(prf_state++, public_key.modulus),
        public_key.modulus);
}

NTL::ZZ CombineShares(
    const PublicKey &public_key,
    const EvaluationKey &eval_key0,
    const Share &share0,
    const EvaluationKey &eval_key1,
    const Share &share1,
    int &prf_state0,
    int &prf_state1)
{
    (void)eval_key0;
    (void)eval_key1;
    (void)prf_state0;
    (void)prf_state1;

    NTL::ZZ result;
    SubMod(result, share1[0], share0[0], public_key.modulus);
    return result;
}
} // namespace osy21::detail

#include "core.hpp"

namespace
{
NTL::ZZ ExtractDiscreteDifferenceLog(
    const ados22::detail::PublicKey &public_key,
    const NTL::ZZ &value)
{
    NTL::ZZ quotient;
    NTL::ZZ remainder;
    NTL::ZZ inverse;
    NTL::ZZ result;

    DivRem(quotient, remainder, value, public_key.modulus);
    InvMod(inverse, remainder, public_key.modulus);
    MulMod(result, quotient, inverse, public_key.modulus);
    return result;
}
} // namespace

namespace ados22::detail
{
void GenerateKeys(
    PublicKey &public_key,
    EvaluationKey &eval_key0,
    EvaluationKey &eval_key1,
    int secret_key_bits)
{
    SecretKey secret_key;
    GenerateElgamalKeys(public_key, secret_key, secret_key_bits);

    RandomBits(eval_key0, secret_key_bits);
    add(eval_key1, eval_key0, secret_key);
}

void EncryptInput(Ciphertext &ciphertext, const PublicKey &public_key, const ZZ &message)
{
    Encrypt(ciphertext[0], public_key, message);
    EncryptWithEmbeddedSecret(ciphertext[1], public_key, message);
}

void ConvertInput(
    Share &share,
    int party,
    const PublicKey &public_key,
    const EvaluationKey &eval_key,
    const Ciphertext &ciphertext,
    int &prf_state)
{
    Share basis;
    basis[0] = party;
    basis[1] = eval_key;
    MultiplyShare(share, party, public_key, eval_key, ciphertext, basis, prf_state);
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
    (void)public_key;
    (void)eval_key;
    (void)prf_state;

    add(sum[0], lhs[0], rhs[0]);
    add(sum[1], lhs[1], rhs[1]);
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

    ZZ left_term;
    ZZ right_term;

    PowerMod(left_term, ciphertext[0][1], share[0], public_key.modulus_square);
    PowerMod(right_term, ciphertext[0][0], -share[1], public_key.modulus_square);
    MulMod(product[0], left_term, right_term, public_key.modulus_square);
    product[0] = ExtractDiscreteDifferenceLog(public_key, product[0]) +
                 PRF_ZZ(prf_state++, public_key.modulus);

    PowerMod(left_term, ciphertext[1][1], share[0], public_key.modulus_square);
    PowerMod(right_term, ciphertext[1][0], -share[1], public_key.modulus_square);
    MulMod(product[1], left_term, right_term, public_key.modulus_square);
    product[1] = ExtractDiscreteDifferenceLog(public_key, product[1]) +
                 PRF_ZZ(prf_state++, public_key.modulus);
}

ZZ CombineShares(
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

    ZZ result;
    SubMod(result, share1[0], share0[0], public_key.modulus);
    return result;
}
} // namespace ados22::detail

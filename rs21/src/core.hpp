#pragma once

#include "dj.hpp"

namespace rs21::detail
{
inline constexpr int kPartyCount = 2;
inline constexpr long kShareComponents = 2;

struct PublicKey
{
    int s;
    DjPublicKey dj_public_key1;
    DjPublicKey dj_public_key2;
    ZZ helper_ciphertext;
    int security_parameter;
};

struct EvaluationKey
{
    ZZ phi;
    ZZ phi_prime;
};

using Ciphertext = ZZ;
using Share = Vec<ZZ>;

void GenerateKeys(PublicKey &public_key, EvaluationKey &eval_key0, EvaluationKey &eval_key1);
void EncryptInput(Ciphertext &ciphertext, const PublicKey &public_key, const ZZ &message);
void ConvertInput(
    Share &share,
    int party,
    const PublicKey &public_key,
    const EvaluationKey &eval_key,
    const Ciphertext &ciphertext,
    int &prf_state);
void AddShares(
    Share &sum,
    int party,
    const PublicKey &public_key,
    const EvaluationKey &eval_key,
    const Share &lhs,
    const Share &rhs,
    int &prf_state);
void MultiplyShare(
    Share &product,
    int party,
    const PublicKey &public_key,
    const EvaluationKey &eval_key,
    const Ciphertext &ciphertext,
    const Share &share,
    int &prf_state);
ZZ CombineShares(
    const PublicKey &public_key,
    const EvaluationKey &eval_key0,
    const Share &share0,
    const EvaluationKey &eval_key1,
    const Share &share1,
    int &prf_state0,
    int &prf_state1);
} // namespace rs21::detail

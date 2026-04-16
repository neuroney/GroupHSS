#pragma once

#include "../../src/core.hpp"

#include <NTL/ZZ.h>

namespace ados22
{
struct Params
{
    int secret_key_bits = 128;
};

struct Context
{
    Params params;
    detail::PublicKey public_key;
    detail::EvaluationKey eval_keys[detail::kPartyCount];
};

struct Ciphertext
{
    detail::Ciphertext value;
};

struct Share
{
    detail::Share value;
};

Context KeyGen(const Params &params = {});
Ciphertext ShareInput(const Context &context, const NTL::ZZ &input);
Share ConvertInput(const Context &context, int party, const Ciphertext &input, int &prf_state);
Share EvalAdd(const Context &context, int party, const Share &lhs, const Share &rhs, int &prf_state);
Share EvalMul(const Context &context, int party, const Ciphertext &input, const Share &rhs, int &prf_state);
NTL::ZZ Reconstruct(
    const Context &context,
    const Share &party0_share,
    const Share &party1_share,
    int &prf_state0,
    int &prf_state1);
} // namespace ados22

#include "osy21/osy21.hpp"

#include <stdexcept>

namespace
{
void ValidateParty(int party)
{
    if (party != 0 && party != 1)
    {
        throw std::invalid_argument("party index must be 0 or 1");
    }
}
} // namespace

namespace osy21
{
Context KeyGen(const Params &params)
{
    Context context;
    context.params = params;
    detail::GenerateKeys(
        context.public_key,
        context.eval_keys[0],
        context.eval_keys[1]);
    return context;
}

Ciphertext ShareInput(const Context &context, const NTL::ZZ &input)
{
    Ciphertext ciphertext;
    detail::EncryptInput(ciphertext.value, context.public_key, input);
    return ciphertext;
}

Share ConvertInput(const Context &context, int party, const Ciphertext &input, int &prf_state)
{
    ValidateParty(party);

    Share share;
    detail::ConvertInput(
        share.value,
        party,
        context.public_key,
        context.eval_keys[party],
        input.value,
        prf_state);
    return share;
}

Share EvalAdd(const Context &context, int party, const Share &lhs, const Share &rhs, int &prf_state)
{
    ValidateParty(party);

    Share share;
    detail::AddShares(
        share.value,
        party,
        context.public_key,
        context.eval_keys[party],
        lhs.value,
        rhs.value,
        prf_state);
    return share;
}

Share EvalMul(const Context &context, int party, const Ciphertext &input, const Share &rhs, int &prf_state)
{
    ValidateParty(party);

    Share share;
    detail::MultiplyShare(
        share.value,
        party,
        context.public_key,
        context.eval_keys[party],
        input.value,
        rhs.value,
        prf_state);
    return share;
}

NTL::ZZ Reconstruct(
    const Context &context,
    const Share &party0_share,
    const Share &party1_share,
    int &prf_state0,
    int &prf_state1)
{
    return detail::CombineShares(
        context.public_key,
        context.eval_keys[0],
        party0_share.value,
        context.eval_keys[1],
        party1_share.value,
        prf_state0,
        prf_state1);
}
} // namespace osy21

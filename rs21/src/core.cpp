#include "core.hpp"

namespace
{
void EnsureShareShape(rs21::detail::Share &share)
{
    if (share.length() != rs21::detail::kShareComponents)
    {
        share.SetLength(rs21::detail::kShareComponents);
    }
}

NTL::ZZ FinalizePartyOutput(
    int party,
    const rs21::detail::PublicKey &public_key,
    const rs21::detail::EvaluationKey &eval_key,
    const rs21::detail::Share &share,
    int &prf_state)
{
    (void)party;
    (void)eval_key;

    NTL::ZZ ciphertext;
    PowerMod(
        ciphertext,
        public_key.helper_ciphertext,
        share[0] - public_key.dj_public_key2.modulus_power_s * share[1],
        public_key.dj_public_key2.modulus_power_s_plus_1);

    NTL::ZZ output;
    rs21::detail::Distinguish(output, public_key.dj_public_key2, ciphertext);
    AddMod(
        output,
        output,
        PRF_ZZ(prf_state++, public_key.dj_public_key1.modulus_power_s),
        public_key.dj_public_key2.modulus_power_s);
    return output;
}
} // namespace

namespace rs21::detail
{
void GenerateKeys(PublicKey &public_key, EvaluationKey &eval_key0, EvaluationKey &eval_key1)
{
    public_key.security_parameter = 1024;
    public_key.s = 3;

    ZZ phi;
    ZZ phi_prime;
    GenerateDjKeys(public_key.dj_public_key1, phi, public_key.s);
    GenerateDjKeys(public_key.dj_public_key2, phi_prime, public_key.s - 2);

    ZZ mu;
    InvMod(mu, phi, public_key.dj_public_key2.modulus_power_s);

    ZZ reduced_modulus_power;
    ZZ nu;
    rem(
        reduced_modulus_power,
        public_key.dj_public_key2.modulus_power_s,
        phi_prime);
    InvMod(nu, reduced_modulus_power, phi_prime);

    EncryptDj(public_key.helper_ciphertext, public_key.dj_public_key2, mu);

    ZZ mixed_bound;
    ZZ security_scale;
    ZZ bound;
    mul(
        mixed_bound,
        public_key.dj_public_key1.modulus,
        public_key.dj_public_key2.modulus);
    power2(security_scale, 128);
    mul(bound, mixed_bound, security_scale);

    RandomBnd(eval_key0.phi, bound);
    RandomBnd(eval_key0.phi_prime, bound);
    eval_key1.phi = eval_key0.phi + phi;
    eval_key1.phi_prime = eval_key0.phi_prime + phi * nu;
}

void EncryptInput(Ciphertext &ciphertext, const PublicKey &public_key, const ZZ &message)
{
    EncryptDj(ciphertext, public_key.dj_public_key1, message);
}

void ConvertInput(
    Share &share,
    int party,
    const PublicKey &public_key,
    const EvaluationKey &eval_key,
    const Ciphertext &ciphertext,
    int &prf_state)
{
    (void)party;
    EnsureShareShape(share);

    ZZ phi_component;
    ZZ phi_prime_component;
    PowerMod(
        phi_component,
        ciphertext,
        eval_key.phi,
        public_key.dj_public_key1.modulus_power_s_plus_1);
    PowerMod(
        phi_prime_component,
        ciphertext,
        eval_key.phi_prime,
        public_key.dj_public_key1.modulus_power_s_plus_1);

    Distinguish(share[0], public_key.dj_public_key1, phi_component);
    Distinguish(share[1], public_key.dj_public_key1, phi_prime_component);

    AddMod(
        share[0],
        share[0],
        PRF_ZZ(prf_state++, public_key.dj_public_key1.modulus_power_s),
        public_key.dj_public_key1.modulus_power_s);
    AddMod(
        share[1],
        share[1],
        PRF_ZZ(prf_state++, public_key.dj_public_key1.modulus_power_s),
        public_key.dj_public_key1.modulus_power_s);
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
    EnsureShareShape(sum);

    AddMod(
        sum[0],
        lhs[0],
        rhs[0],
        public_key.dj_public_key1.modulus_power_s);
    AddMod(
        sum[1],
        lhs[1],
        rhs[1],
        public_key.dj_public_key1.modulus_power_s);

    AddMod(
        sum[0],
        sum[0],
        PRF_ZZ(prf_state++, public_key.dj_public_key1.modulus_power_s),
        public_key.dj_public_key1.modulus_power_s);
    AddMod(
        sum[1],
        sum[1],
        PRF_ZZ(prf_state++, public_key.dj_public_key1.modulus_power_s),
        public_key.dj_public_key1.modulus_power_s);
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
    EnsureShareShape(product);

    ZZ primary_component;
    ZZ secondary_component;
    PowerMod(
        primary_component,
        ciphertext,
        share[0],
        public_key.dj_public_key1.modulus_power_s_plus_1);
    PowerMod(
        secondary_component,
        ciphertext,
        share[1],
        public_key.dj_public_key1.modulus_power_s_plus_1);

    Distinguish(product[0], public_key.dj_public_key1, primary_component);
    Distinguish(product[1], public_key.dj_public_key1, secondary_component);

    AddMod(
        product[0],
        product[0],
        PRF_ZZ(prf_state++, public_key.dj_public_key1.modulus_power_s),
        public_key.dj_public_key1.modulus_power_s);
    AddMod(
        product[1],
        product[1],
        PRF_ZZ(prf_state++, public_key.dj_public_key1.modulus_power_s),
        public_key.dj_public_key1.modulus_power_s);
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
    ZZ output0 = FinalizePartyOutput(
        0,
        public_key,
        eval_key0,
        share0,
        prf_state0);
    ZZ output1 = FinalizePartyOutput(
        1,
        public_key,
        eval_key1,
        share1,
        prf_state1);

    ZZ result;
    SubMod(
        result,
        output1,
        output0,
        public_key.dj_public_key2.modulus_power_s);
    return result;
}
} // namespace rs21::detail

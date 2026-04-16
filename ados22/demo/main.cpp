#include "ados22/ados22.hpp"

#include <iostream>

int main()
{
    const ados22::Params params{};
    const ados22::Context context = ados22::KeyGen(params);

    const ados22::Ciphertext x = ados22::ShareInput(context, NTL::ZZ(45));
    const ados22::Ciphertext one = ados22::ShareInput(context, NTL::ZZ(1));

    int prf_state0 = 0;
    int prf_state1 = 0;

    const ados22::Share x0 = ados22::ConvertInput(context, 0, x, prf_state0);
    const ados22::Share x1 = ados22::ConvertInput(context, 1, x, prf_state1);
    const ados22::Share one0 = ados22::ConvertInput(context, 0, one, prf_state0);
    const ados22::Share one1 = ados22::ConvertInput(context, 1, one, prf_state1);

    const ados22::Share x_squared0 = ados22::EvalMul(context, 0, x, x0, prf_state0);
    const ados22::Share x_squared1 = ados22::EvalMul(context, 1, x, x1, prf_state1);

    const ados22::Share result0 = ados22::EvalAdd(context, 0, x_squared0, one0, prf_state0);
    const ados22::Share result1 = ados22::EvalAdd(context, 1, x_squared1, one1, prf_state1);

    const NTL::ZZ result =
        ados22::Reconstruct(context, result0, result1, prf_state0, prf_state1);

    std::cout << "Protocol: ADOS22" << std::endl;
    std::cout << "Result: " << result << std::endl;
    return 0;
}

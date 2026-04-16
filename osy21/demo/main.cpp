#include "osy21/osy21.hpp"

#include <iostream>

int main()
{
    const osy21::Params params{};
    const osy21::Context context = osy21::KeyGen(params);

    const osy21::Ciphertext x = osy21::ShareInput(context, NTL::ZZ(45));
    const osy21::Ciphertext one = osy21::ShareInput(context, NTL::ZZ(1));

    int prf_state0 = 0;
    int prf_state1 = 0;

    const osy21::Share x0 = osy21::ConvertInput(context, 0, x, prf_state0);
    const osy21::Share x1 = osy21::ConvertInput(context, 1, x, prf_state1);
    const osy21::Share one0 = osy21::ConvertInput(context, 0, one, prf_state0);
    const osy21::Share one1 = osy21::ConvertInput(context, 1, one, prf_state1);

    const osy21::Share x_squared0 = osy21::EvalMul(context, 0, x, x0, prf_state0);
    const osy21::Share x_squared1 = osy21::EvalMul(context, 1, x, x1, prf_state1);

    const osy21::Share result0 = osy21::EvalAdd(context, 0, x_squared0, one0, prf_state0);
    const osy21::Share result1 = osy21::EvalAdd(context, 1, x_squared1, one1, prf_state1);

    const NTL::ZZ result =
        osy21::Reconstruct(context, result0, result1, prf_state0, prf_state1);

    std::cout << "Protocol: OSY21" << std::endl;
    std::cout << "Result: " << result << std::endl;
    return 0;
}

#include "rs21/rs21.hpp"

#include <iostream>

int main()
{
    const rs21::Params params{};
    const rs21::Context context = rs21::KeyGen(params);

    const rs21::Ciphertext x = rs21::ShareInput(context, NTL::ZZ(45));
    const rs21::Ciphertext one = rs21::ShareInput(context, NTL::ZZ(1));

    int prf_state0 = 0;
    int prf_state1 = 0;

    const rs21::Share x0 = rs21::ConvertInput(context, 0, x, prf_state0);
    const rs21::Share x1 = rs21::ConvertInput(context, 1, x, prf_state1);
    const rs21::Share one0 = rs21::ConvertInput(context, 0, one, prf_state0);
    const rs21::Share one1 = rs21::ConvertInput(context, 1, one, prf_state1);

    const rs21::Share x_squared0 = rs21::EvalMul(context, 0, x, x0, prf_state0);
    const rs21::Share x_squared1 = rs21::EvalMul(context, 1, x, x1, prf_state1);

    const rs21::Share result0 = rs21::EvalAdd(context, 0, x_squared0, one0, prf_state0);
    const rs21::Share result1 = rs21::EvalAdd(context, 1, x_squared1, one1, prf_state1);

    const NTL::ZZ result =
        rs21::Reconstruct(context, result0, result1, prf_state0, prf_state1);

    std::cout << "Protocol: RS21" << std::endl;
    std::cout << "Result: " << result << std::endl;
    return 0;
}

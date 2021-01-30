
#include "seal/seal.h"
#include "examples.h"
#include <iostream>


using namespace std;
using namespace seal;
size_t poly_modulus_degree = 8192;

void rotate_sum(Evaluator & evaluator, Ciphertext & ciphertext, const GaloisKeys & keys) {
    const int poly_modulus_degree_power = log2(poly_modulus_degree);
    Ciphertext rotated;
    for (int i = 0; i < poly_modulus_degree_power - 1; ++i) {
        evaluator.rotate_vector(ciphertext, pow(2, i), keys, rotated);
        evaluator.add_inplace(ciphertext, rotated);
    }
}
int main()
{


    
    //bfv_basics();
    //example_encoders();
    //example_levels();
    //定义加密参数
    void test1(); // 声明一下test1函数，源代码在demotest里
    test1();
    //example_ckks_basics();
    //example_rotation();
    return 0;
}



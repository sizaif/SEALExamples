
#include "seal/seal.h"
#include "examples.h"
#include <iostream>
#include <torch/torch.h>
#include <torch/script.h>

using namespace std;
using namespace seal;

int main()
{
    //bfv_basics();
    //example_encoders();
    //example_levels();
    //定义加密参数
    //void test1(); // 声明一下test1函数，源代码在demotest里
    //test1();
    //example_ckks_basics();
    //example_rotation();
    
    torch::Tensor tensor = torch::rand({ 5,3 });
    std::cout << tensor << std::endl;
    /*
    torch::Tensor tensor = torch::rand({ 5,3 });
    std::cout << tensor << std::endl;

    return EXIT_SUCCESS;
    */


    return 0;
}



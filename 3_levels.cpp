#include "examples.h"
#include "seal/seal.h"

using namespace std;
using namespace seal;


void example_levels() {
	print_example_banner("Example: Levels");

	EncryptionParameters parms(scheme_type::bfv);
	size_t poly_modulus_degree = 8192;
	parms.set_poly_modulus_degree(poly_modulus_degree);
	/*
    在这个例子中，我们使用了一个自定义的coeff_modulus， c由5个质数组成的50, 30, 30, 50, 50 位素数. 

        CoeffModulus::MaxBitCount(poly_modulus_degree)
    returns 218 (greater than 50+30+30+50+50=210).
	由于模量切换链，5个素数的顺序是重要的。最后一个质数有特殊的含义，我们称之为“特殊质数”。
	因此,第一个参数设置在模切换链只有一个涉及到特殊的prime
	创建所有密钥对象，如SecretKey在这个最高的层次。所有数据对象，如密文，只能在较低的水平。
	这个特殊质数应该与在coeff_modulus中的其他素数的最大质数一样大
                  special prime +---------+
                                      |
                                      v
    coeff_modulus: { 50, 30, 30, 50, 50 }  +---+  Level 4 (all keys; `key level')
                                               |
                                               |
        coeff_modulus: { 50, 30, 30, 50 }  +---+  Level 3 (highest `data level')
                                               |
                                               |
            coeff_modulus: { 50, 30, 30 }  +---+  Level 2
                                               |
                                               |
                coeff_modulus: { 50, 30 }  +---+  Level 1
                                               |
                                               |
                    coeff_modulus: { 50 }  +---+  Level 0 (lowest level)
	*/
    parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, { 50, 30, 30, 50, 50 }));
    /*
    在这个例子中，plain_modulus没有发挥太大的作用;我们选择一些合理的价值
    */
    parms.set_plain_modulus(PlainModulus::Batching(poly_modulus_degree, 20));
    SEALContext context(parms);
    print_parameters(context);
    cout << endl;

    /*
    * 有方便的访问方法 SEALContext::ContextData 
        SEALContext::key_context_data(): access to key level ContextData
        SEALContext::first_context_data(): access to highest data level ContextData
        SEALContext::last_context_data(): access to lowest level ContextData

    */
    //遍历该链并打印每组参数的parms_id。
    print_line(__LINE__);
    cout << "Print the modulus switching chain." << endl;
    auto context_data = context.key_context_data();
    cout << "----> Level (chain index): " << context_data->chain_index();
    cout << " ...... key_context_data()" << endl;
    cout << "      parms_id: " << context_data->parms_id() << endl;
    cout << "      coeff_modulus primes: ";
    cout << hex;
    for (const auto& prime : context_data->parms().coeff_modulus())
    {
        cout << prime.value() << " ";
    }
    cout << dec << endl;
    cout << "\\" << endl;
    cout << " \\-->";
    return;
}
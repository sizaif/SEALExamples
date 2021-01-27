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
    //首先打印关键级别参数信息
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
    
    //接下来迭代其余的
    context_data = context.first_context_data();
    while (context_data)
    {
        cout << " Level (chain index): " << context_data->chain_index();
        if (context_data->parms_id() == context.first_parms_id())
        {
            cout << " ...... first_context_data()" << endl;
        }
        else if (context_data->parms_id() == context.last_parms_id())
        {
            cout << " ...... last_context_data()" << endl;
        }
        else
        {
            cout << endl;
        }
        cout << "      parms_id: " << context_data->parms_id() << endl;
        cout << "      coeff_modulus primes: ";
        cout << hex; // 16进制输出
        for (const auto& prime : context_data->parms().coeff_modulus())
        {
            cout << prime.value() << " ";
        }
        cout << dec << endl;
        cout << "\\" << endl;
        cout << " \\-->";

        /*
        Step forward in the chain.
        */
        context_data = context_data->next_context_data();
    }
    cout << " End of chain reached" << endl << endl;

    //我们创建一些keys并检查它们是否确实出现在最高层。
    KeyGenerator keygen(context);
    auto secret_key = keygen.secret_key();
    PublicKey public_key;
    keygen.create_public_key(public_key);
    RelinKeys relin_keys;
    keygen.create_relin_keys(relin_keys);

    print_line(__LINE__);
    cout << "Print the parameter IDs of generated elements." << endl;
    cout << "    + public_key:  " << public_key.parms_id() << endl;
    cout << "    + secret_key:  " << secret_key.parms_id() << endl;
    cout << "    + relin_keys:  " << relin_keys.parms_id() << endl;

    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);

    /*
    * 在BFV方案中，明文不携带parms_id，而密文携带parms_id。
    请注意新加密的密文如何在最高数据级别。
    */
    Plaintext plain("1x^3 + 2x^2 + 3x^1 + 4");
    Ciphertext encrypted;
    encryptor.encrypt(plain, encrypted);
    cout << "    + plain:       " << plain.parms_id() << " (not set in BFV)" << endl;
    cout << "    + encrypted:   " << encrypted.parms_id() << endl << endl;

    /*
    * “Modulus switching”是一种降低密文参数的技术在链中 Evaluator::mod_switch_to_next总是切换到
    下一级链，而Evaluator::mod_switch_to切换到在对应于给定parms_id的链上设置的参数。然而,它
    是不可能在链条向上切换的。
    */
    print_line(__LINE__);
    cout << "Perform modulus switching on encrypted and print." << endl;
    context_data = context.first_context_data();
    cout << "---->";
    while (context_data->next_context_data())
    {
        cout << " Level (chain index): " << context_data->chain_index() << endl;
        cout << "      parms_id of encrypted: " << encrypted.parms_id() << endl;
        cout << "      Noise budget at this level: " << decryptor.invariant_noise_budget(encrypted) << " bits" << endl;
        cout << "\\" << endl;
        cout << " \\-->";
        evaluator.mod_switch_to_next_inplace(encrypted);
        context_data = context_data->next_context_data();
    }
    cout << " Level (chain index): " << context_data->chain_index() << endl;
    cout << "      parms_id of encrypted: " << encrypted.parms_id() << endl;
    cout << "      Noise budget at this level: " << decryptor.invariant_noise_budget(encrypted) << " bits" << endl;
    cout << "\\" << endl;
    cout << " \\-->";
    cout << " End of chain reached" << endl << endl;
    /*
    在这一点上，很难看到这样做有任何好处:我们损失了巨大噪音预算(即计算能力)没有任何回报。
    解密仍能工作。
    然而，有一个隐藏的好处:密文的大小取决于系数模数中素数数的线性关系。
    因此,如果有不需要或不打算对给定的对象执行任何进一步的计算密文，
    我们不妨把它切换到最小的(最后的)集合参数，然后将其发送回密钥持有者解密。
    此外，噪音损失预算实际上根本不是一个问题
    
    */
    print_line(__LINE__);
    cout << "Decrypt still works after modulus switching." << endl;
    decryptor.decrypt(encrypted, plain);
    cout << "    + Decryption of encrypted: " << plain.to_string();
    cout << " ...... Correct." << endl << endl;
    /*
    * 因此,如果有不需要或不打算对给定的对象执行任何进一步的计算密文，
    * 我们不妨把它切换到最小的(最后的)集合参数，然后将其发送回密钥持有者解密。
    * 此外，噪音损失预算实际上根本不是一个问题
    * 首先，我们重新创建原始密文并执行一些计算。
    * 
    */
    cout << "Computation is more efficient with modulus switching." << endl;
    print_line(__LINE__);
    cout << "Compute the 8th power." << endl;
    encryptor.encrypt(plain, encrypted);
    cout << "    + Noise budget fresh:                   " << decryptor.invariant_noise_budget(encrypted) << " bits"
        << endl;
    evaluator.square_inplace(encrypted);
    evaluator.relinearize_inplace(encrypted, relin_keys);
    cout << "    + Noise budget of the 2nd power:         " << decryptor.invariant_noise_budget(encrypted) << " bits"
        << endl;
    evaluator.square_inplace(encrypted);
    evaluator.relinearize_inplace(encrypted, relin_keys);
    cout << "    + Noise budget of the 4th power:         " << decryptor.invariant_noise_budget(encrypted) << " bits"
        << endl;
    /*
    在这种情况下 modulus switching 对噪声预算完全没有影响。
    */
    evaluator.mod_switch_to_next_inplace(encrypted);
    cout << "    + Noise budget after modulus switching:  " << decryptor.invariant_noise_budget(encrypted) << " bits"
        << endl;
    /*
    * 这意味着降低一些系数是没有任何害处的在做了足够的计算之后。
    * 在某些情况下，人们可能稍微早一点切换到一个较低的级别，实际上牺牲了一些过程中的噪音预算
    * 以用更小的参数来获得计算性能
    * 我们从打印出来的数据中可以看到，当噪音预算降到25位左右时，下一个modulus switch应该理想地完成。
    */

    evaluator.square_inplace(encrypted);
    evaluator.relinearize_inplace(encrypted, relin_keys);
    cout << "    + Noise budget of the 8th power:         " << decryptor.invariant_noise_budget(encrypted) << " bits"
        << endl;
    evaluator.mod_switch_to_next_inplace(encrypted);
    cout << "    + Noise budget after modulus switching:  " << decryptor.invariant_noise_budget(encrypted) << " bits"
        << endl;
    /*
    * 此时，密文仍能正确解密，体积很小，而且计算效率也尽可能高。
    * 注意，解密器可以用来解密在modulus switching链中任意层次一个密文
    */
    decryptor.decrypt(encrypted, plain);
    cout << "    + Decryption of the 8th power (hexadecimal) ...... Correct." << endl;
    cout << "    " << plain.to_string() << endl << endl;
    /*
    * 在BFV中不需要modulus switching
    * 在某些情况下，用户可能会不想创建modulus switching链，
    * 只实现最高的两个level（key level and highest data level)
    * 这可以通过将bool值' false'传递给SEALContext的构造函数来实现。
    */
    context = SEALContext(parms, false);
    /*
    * 我们可以检查确实只创建了模数交换链最高的两层
    */
    cout << "Optionally disable modulus switching chain expansion." << endl;
    print_line(__LINE__);
    cout << "Print the modulus switching chain." << endl;
    cout << "---->";
    for (context_data = context.key_context_data(); context_data; context_data = context_data->next_context_data())
    {
        cout << " Level (chain index): " << context_data->chain_index() << endl;
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
    }
    cout << " End of chain reached" << endl << endl;
    
    return;
}
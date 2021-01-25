
#include "seal/seal.h"
#include "examples.h"
#include <iostream>

using namespace std;
using namespace seal;


void bfv_basics()
{
    print_example_banner("Example: BFV Basics");

    EncryptionParameters parms(scheme_type::bfv); //声明HE 使用的模式
    // 设置 3 个参数
    size_t poly_modulus_degree = 4096;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));
    parms.set_plain_modulus(1024); // 明文 MOD数 (2的倍数, 素数最好)

    //创建一个context
    SEALContext context(parms);

    print_line(__LINE__);
    cout << "Set encryption parameters and print" << endl;
    print_parameters(context);
    cout << "Hello World!" << endl;
    cout << "Parameter validation (success): " << context.parameter_error_message() << endl;

    cout << endl;
    cout << "~~~~~~ A naive way to calculate 4(x^2+1)(x+1)^2. ~~~~~~" << endl;

    KeyGenerator keygen(context); // 密钥类
    SecretKey secret_key = keygen.secret_key(); // 创建私钥
    PublicKey public_key;
    keygen.create_public_key(public_key); // 创建公钥


    Encryptor encryptor(context, public_key);// 加密类,只需要公钥即可;


    Evaluator evaluator(context); // 评估计算类

    Decryptor decryptor(context, secret_key);  // 解密类
    /**
    4x^4 + 8x^3 + 8x^2 + 8x + 4
    **/

    print_line(__LINE__);
    int x = 6;
    Plaintext x_plain(to_string(x));
    //x_plain.to_string() 转换成16进制输出
    cout << "Express x = " + to_string(x) + " as a plaintext polynomial 0x" + x_plain.to_string() + "." << endl;

    print_line(__LINE__);
    Ciphertext x_encrypted;// 密文类
    cout << "Encrypt x_plain to x_encrypted." << endl;

    encryptor.encrypt(x_plain, x_encrypted);

    cout << "    + size of freshly encrypted x: " << x_encrypted.size() << endl;

    /*
There is plenty of noise budget left in this freshly encrypted ciphertext. 噪声预算，当噪音预算降低到0的时候，计算结果不正确
*/
    cout << "    + noise budget in freshly encrypted x: " << decryptor.invariant_noise_budget(x_encrypted) << " bits"
        << endl;

    Plaintext x_decrypted;
    cout << "    + decryption of x_encrypted: ";
    decryptor.decrypt(x_encrypted, x_decrypted);
    cout << "0x" << x_decrypted.to_string() << " ...... Correct." << endl;

    print_line(__LINE__);
    cout << "Compute x_sq_plus_one (x^2+1)." << endl;


    Ciphertext x_sq_plus_one;
    evaluator.square(x_encrypted, x_sq_plus_one); // 计算平方, 结果输出到 x_sq_plus_one 中
    Plaintext plain_one("1"); // 明文 1
    evaluator.add_plain_inplace(x_sq_plus_one, plain_one); // x_sq_plus_one = x_sq_plus_one + plain_one

    /**
    加密的乘法导致输出密文的大小增加。
    更准确地说，如果输入密文的大小为M和N，则输出
    同态乘法后的密文大小为M+N-1。
    **/

    cout << "    + size of x_sq_plus_one: " << x_sq_plus_one.size() << endl;
    cout << "    + noise budget in x_sq_plus_one: " << decryptor.invariant_noise_budget(x_sq_plus_one) << " bits"
        << endl;

    /*
    * 计算4个多项式样例
    * 4x^4 + 8x^3 + 8x^2 + 8x + 4
    * 4x^4 + 8x^3 + 8x^2 + 8x + 4 = 4(x + 1)^2 * (x^2 + 1) 转换成 4(x + 1)^2 * (x^2 + 1) 降低多项式系数
    */
    stringstream ss2;//字符串流 ,做字符转换用
    int d2;
    // 密文计算(x^2+1)  的解密结果为:
    Plaintext decrypted_result;
    cout << "    + decryption of x_sq_plus_one : ";
    decryptor.decrypt(x_sq_plus_one, decrypted_result);
    ss2.clear();
    ss2 << hex << decrypted_result.to_string(); // 十六进制输出到ss2，
    ss2 >> d2; // ss2 输出十进制到 d2
    cout << "HEX: 0x" << decrypted_result.to_string() << " Integer: " << d2 << " .... Correct. " << endl;

    /*
    接着密文计算 (x + 1)^2.
    */
    print_line(__LINE__);
    cout << "Compute x_plus_one_sq ((x+1)^2)." << endl;

    Ciphertext x_plus_one_sq;
    evaluator.add_plain(x_encrypted, plain_one, x_plus_one_sq); //密文 x_plus_one_sq = x_encrypted + plain_one (x+1)
    evaluator.square_inplace(x_plus_one_sq); //  x_plus_one_sq = x_plus_one_sq * x_plus_one_sq;

    cout << "    + size of x_plus_one_sq: " << x_plus_one_sq.size() << endl;
    cout << "    + noise budget in x_plus_one_sq: " << decryptor.invariant_noise_budget(x_plus_one_sq) << " bits"
        << endl;
    cout << "    + decryption of x_plus_one_sq: ";
    decryptor.decrypt(x_plus_one_sq, decrypted_result);
    ss2.clear();
    ss2 << hex << decrypted_result.to_string(); // 十六进制输出到ss2，
    ss2 >> d2; // ss2 输出十进制到 d2
    cout << "Hex: Ox" << decrypted_result.to_string() << " Integer: " << d2 << " .... Correct. " << endl;


    /*
        最终计算 (x^2 + 1) * (x + 1)^2 * 4.
    */
    print_line(__LINE__);
    cout << "Compute encrypted_result (4(x^2+1)(x+1)^2)." << endl;
    Ciphertext encrypted_result;
    Plaintext plain_four("4");
    evaluator.multiply_plain_inplace(x_sq_plus_one, plain_four); // x_sq_plus_one = x_sq_plus_one * 4;
    evaluator.multiply(x_sq_plus_one, x_plus_one_sq, encrypted_result); //  密文encrypted_result = x_sq_plus_one * x_plus_one_sq ;

    cout << "    + size of encrypted_result: " << encrypted_result.size() << endl;
    cout << "    + noise budget in encrypted_result: " << decryptor.invariant_noise_budget(encrypted_result) << " bits"
        << endl;
    cout << "NOTE: Decryption can be incorrect if noise budget is zero." << endl;

    cout << endl;
    cout << "~~~~~~ A better way to calculate 4(x^2+1)(x+1)^2. ~~~~~~" << endl;

    decryptor.decrypt(encrypted_result, decrypted_result);
    stringstream ss3;
    ss3.clear();
    ss3 << hex << decrypted_result.to_string();
    ss3 >> d2; // ss2 输出十进制到 d2
    cout << d2 << " " << decrypted_result.to_string() << endl; // 得到的结果不正确

    /*
    * 利用Relinearization 线性化 对运算进行优化
    */
    print_line(__LINE__);
    cout << "Generate relinearization keys." << endl;
    RelinKeys relin_keys; // 做线性化类
    keygen.create_relin_keys(relin_keys); // 创建线性化密钥
    /*
        We now repeat the computation relinearizing after each multiplication.
        我们在每次乘法之后重复重新线性化的计算。
    */
    print_line(__LINE__);
    cout << "Compute and relinearize x_squared (x^2)," << endl;
    cout << string(13, ' ') << "then compute x_sq_plus_one (x^2+1)" << endl;
    Ciphertext x_squared;

    evaluator.square(x_encrypted, x_squared);
    cout << "    + size of x_squared: " << x_squared.size() << endl;

    evaluator.relinearize_inplace(x_squared, relin_keys);// 重新线性化大小到2以内

    cout << "    + size of x_squared (after relinearization): " << x_squared.size() << endl;

    evaluator.add_plain(x_squared, plain_one, x_sq_plus_one); // x_sq_plus_one = x_squared +  plain_one;

    cout << "    + noise budget in x_sq_plus_one: " << decryptor.invariant_noise_budget(x_sq_plus_one) << " bits"
        << endl;
    cout << "    + decryption of x_sq_plus_one: ";

    decryptor.decrypt(x_sq_plus_one, decrypted_result);
    ss2.clear();
    ss2 << hex << decrypted_result.to_string();
    ss2 >> d2;
    cout << "Hex: 0x" << decrypted_result.to_string() << " Integer: " << d2 << " ...... Correct. (x^2 + 1 ) " << endl;

    print_line(__LINE__);
    Ciphertext x_plus_one;
    cout << "Compute x_plus_one (x+1)," << endl;
    cout << string(13, ' ') << "then compute and relinearize x_plus_one_sq ((x+1)^2)." << endl;

    evaluator.add_plain(x_encrypted, plain_one, x_plus_one);// x_plus_one = x_encrypted +  plain_one;
    evaluator.square(x_plus_one, x_plus_one_sq);// x_plus_one_sq =  x_plus_one * x_plus_one;

    cout << "    + size of x_plus_one_sq: " << x_plus_one_sq.size() << endl;

    evaluator.relinearize_inplace(x_plus_one_sq, relin_keys); // 大小线性优化到2内

    cout << "    + noise budget in x_plus_one_sq: " << decryptor.invariant_noise_budget(x_plus_one_sq) << " bits"
        << endl;
    cout << "    + decryption of x_plus_one_sq: ";
    ss3.clear();
    decryptor.decrypt(x_plus_one_sq, decrypted_result);
    ss3 << hex << decrypted_result.to_string();
    ss3 >> d2;
    cout << "Hex: 0x" << decrypted_result.to_string() << " Integer: " << d2 << " ...... Correct." << endl;

    print_line(__LINE__);
    cout << "Compute and relinearize encrypted_result (4(x^2+1)(x+1)^2)." << endl;

    evaluator.multiply_plain_inplace(x_sq_plus_one, plain_four); //  x_sq_plus_one = x_sq_plus_one * plain_four
    evaluator.multiply(x_sq_plus_one, x_plus_one_sq, encrypted_result);// encrypted_result = x_sq_plus_one * x_plus_one_sq

    cout << "    + size of encrypted_result: " << encrypted_result.size() << endl;

    evaluator.relinearize_inplace(encrypted_result, relin_keys); // 线性优化

    cout << "    + size of encrypted_result (after relinearization): " << encrypted_result.size() << endl;
    cout << "    + noise budget in encrypted_result: " << decryptor.invariant_noise_budget(encrypted_result) << " bits"
        << endl;

    cout << endl;
    cout << "NOTE: Notice the increase in remaining noise budget." << endl;

    print_line(__LINE__);
    cout << "Decrypt encrypted_result (4(x^2+1)(x+1)^2)." << endl;

    ss3.clear();
    decryptor.decrypt(encrypted_result, decrypted_result);
    ss3 << hex << decrypted_result.to_string();
    ss3 >> d2;
    cout << "    + decryption of 4(x^2+1)(x+1)^2 ,after Mod = Hex: 0x" << decrypted_result.to_string()
        << " Integer:" << d2 << " ...... Correct.(4(x^2+1)(x+1)^2)" << endl;
    /*
    * 对于 x=6, 4(x^2+1)(x+1)^2 = 7252. 因为 plaintext modulus MOD被设置为 1024,
    * 所以结果%1024.故 7252 % 1024 == 84, 或者16进制： 0x54
    */
    print_line(__LINE__);
    cout << "An example of invalid parameters" << endl;
    parms.set_poly_modulus_degree(2048);
    context = SEALContext(parms);
    print_parameters(context);
    cout << "Parameter validation (failed): " << context.parameter_error_message() << endl << endl;

}



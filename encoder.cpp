#include "examples.h"

using namespace std;
using namespace seal;

void example_batch_encoder() {
    print_example_banner("Example: Encoders / Batch Encoder");
     
    /*
    [BatchEncoder] (For BFV scheme only)

    Let N 表示 poly_modulus_degree ; T 表示 plain_modulus. Batching
    allows the BFV plaintext polynomials to be viewed as 2-by-(N/2) matrices, with
    each element an integer modulo T. 在矩阵视图中，加密操作法案在加密的矩阵上,
    allowing the user to obtain speeds-ups of several orders of magnitude in fully vectorizable computations. 
    Thus, in all but the simplest computations, batching should be the preferred method to use
    with BFV, and when used properly will result in implementations outperforming
    anything done without batching.
    */

    EncryptionParameters parms(scheme_type::bfv);
    size_t poly_modulus_degree = 8192;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));

    parms.set_plain_modulus(PlainModulus::Batching(poly_modulus_degree, 20)); 
    //PlainModulus::Batching(poly_modulus_degree, 20) 产生20位的素数

    SEALContext context(parms);
    print_parameters(context);
    cout << endl;

    // 检测是否成功启用
    auto qualifiers = context.first_context_data()->qualifiers();
    cout << "Batching enabled: " << boolalpha << qualifiers.using_batching << endl;
    KeyGenerator keygen(context);
    SecretKey secret_key = keygen.secret_key();
    PublicKey public_key;
    keygen.create_public_key(public_key);
    RelinKeys relin_keys;
    keygen.create_relin_keys(relin_keys);
    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);


    BatchEncoder batch_encoder(context);

    size_t slot_count = batch_encoder.slot_count();
    size_t row_size = slot_count / 2;
    cout << "Plaintext matrix slot_count size: " << slot_count << endl;
    cout << "Plaintext matrix row size: " << row_size << endl;
    /*
    * 声明一个vector，长度为slot_count， 默为 0 
    * 形式为： 2*(slot_count/2) 的二维矩阵
    * [0...............row_size]
    * [row_size......slot_count]
    */
    vector<uint64_t> pod_matrix(slot_count, 0ULL); // 
    
    pod_matrix[0] = 0ULL;
    pod_matrix[1] = 1ULL;
    pod_matrix[2] = 2ULL;
    pod_matrix[3] = 3ULL;
    pod_matrix[row_size] = 4ULL;
    pod_matrix[row_size + 1] = 5ULL;
    pod_matrix[row_size + 2] = 6ULL;
    pod_matrix[row_size + 3] = 7ULL;

    cout << "Input plaintext matrix:" << endl;
    /*
    * 这个print_matrix不会打印矩阵的每一列,只打印每一行的前5个和最后5个
    * [ 0,  1,  2,  3,  0,  0, ...,  0 ]
    * [ 4,  5,  6,  7,  0,  0, ...,  0 ]
    */
    print_matrix(pod_matrix, row_size);

    /*
    首先，我们使用BatchEncoder将矩阵编码成一个明文多项式。
    */
    Plaintext plain_matrix;
    print_line(__LINE__);
    cout << "Encode plaintext matrix:" << endl;
    /*
     从给定的矩阵创建一个明文,"批量处理"一个给定的矩阵 Mod (plaintext modulus) 然后将结果存储到
     plaintext类，输入的vecotr的大小 <= 多项式模的次数(poly_modulus_degree)
    */
    batch_encoder.encode(pod_matrix, plain_matrix);


    /*
    我们可以立即解码以验证编码的正确性. 但注意，还未进行加密或解密
    */
    vector<uint64_t> pod_result;
    cout << "    + Decode plaintext matrix ...... Correct." << endl;

    batch_encoder.decode(plain_matrix, pod_result);
    print_matrix(pod_result, row_size);

    /*
    接下来，我们加密已编码的明文。
    */
    Ciphertext encrypted_matrix;
    print_line(__LINE__);
    cout << "Encrypt plain_matrix to encrypted_matrix." << endl;
    encryptor.encrypt(plain_matrix, encrypted_matrix);
    cout << "    + Noise budget in encrypted_matrix: " << decryptor.invariant_noise_budget(encrypted_matrix) << " bits"
        << endl;
    /*
    * 对密文的操作导致在所有8192(poly_modulus_degree)个slot(矩阵元素)中同时执行同态操作。为了说明这一点，我们构造了另一个明文矩阵：


         [ 1,  2,  1,  2,  1,  2, ..., 2 ]
         [ 1,  2,  1,  2,  1,  2, ..., 2 ]

     然后把它编码成明文。
     */
    vector<uint64_t> pod_matrix2;
    for (size_t i = 0; i < slot_count; i++)
    {
        pod_matrix2.push_back((i & size_t(0x1)) + 1);
    }
    Plaintext plain_matrix2;
    batch_encoder.encode(pod_matrix2, plain_matrix2);
    cout << endl;
    cout << "Second input plaintext matrix:" << endl;
    print_matrix(pod_matrix2, row_size);
    
    /*
     现在我们将第二个(明文)矩阵添加到加密矩阵中，并求sum^2。
     */
    print_line(__LINE__);
    cout << "Sum, square, and relinearize." << endl;
    evaluator.add_plain_inplace(encrypted_matrix, plain_matrix2); // encrypted_matrix = ncrypted_matrix +　plain_matrix2
    evaluator.square_inplace(encrypted_matrix);// encrypted_matrix = encrypted_matrix * encrypted_matrix;
    evaluator.relinearize_inplace(encrypted_matrix, relin_keys); // 序列化


    /*
    查看剩余噪音预算
    */
    cout << "    + Noise budget in result: " << decryptor.invariant_noise_budget(encrypted_matrix) << " bits" << endl;
    /*
    我们将加密的 数据进行解密并解码并验证结果
    */
    Plaintext plain_result;
    print_line(__LINE__);
    cout << "Decrypt and decode result." << endl;
    decryptor.decrypt(encrypted_matrix, plain_result);

    batch_encoder.decode(plain_result, pod_result);
    
    cout << "    + Result plaintext matrix ...... Correct." << endl;
    print_matrix(pod_result, row_size);
    /*
    当所需的加密计算高度可并行化时，批处理允许我们有效地使用全明文多项式。
    但是，它并没有解决这个文件开头提到的另一个问题:
    每个槽只包含一个整数模的明文模量，除非明文模量非常大，
    否则我们可以很快遇到数据类型溢出，并在需要整数计算时会得到意外的结果。
    注意，溢出并不能以加密的形式检测到。CKKS方案(以及CKKSEncoder)解决了数据类型溢出问题，
    但代价是只产生近似的结果。
    
    */

}
void example_ckks_encoder() {

}
void example_encoders()
{
    print_example_banner("Example: Encoders");

    /*
    Run all encoder examples.
    */
    example_batch_encoder();
    example_ckks_encoder();
}
#include "examples.h"

using namespace std;
using namespace seal;


void example_ckks_basics() {
	
	print_example_banner("Example: CKKS Basics");
	

	/*
	In this example we demonstrate evaluating a polynomial function

		PI*x^3 + 0.4*x + 1

	on encrypted floating-point input data x for a set of 4096 equidistant points
	in the interval [0, 1]. This example demonstrates many of the main features
	of the CKKS scheme, but also the challenges in using it.

	We start by setting up the CKKS scheme.
	*/

	EncryptionParameters parms(scheme_type::ckks);
	
	size_t poly_modulus_degree = 8192;  //long long unsigned int
	parms.set_poly_modulus_degree(poly_modulus_degree);
	parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, { 60, 40, 40, 60 }));
	/*
	* 我们选择初始比例为2^40 
	* this leaves us 60-40=20 bits of precision before the decimal point, and enough (roughly
    10-20 bits) of precision after the decimal point. Since our intermediate
    primes are 40 bits (in fact, they are very close to 2^40), we can achieve
    scale stabilization as described above.
	*/
	double scale = pow(2.0, 40);

	SEALContext context(parms);
	print_parameters(context);
	cout << endl;

	KeyGenerator keygen(context);
	auto secret_key = keygen.secret_key();
	PublicKey public_key;
	keygen.create_public_key(public_key);
	RelinKeys relin_keys;
	keygen.create_relin_keys(relin_keys);
	GaloisKeys galois_keys;
	keygen.create_galois_keys(galois_keys);

	Encryptor encryptor(context, public_key);
	Evaluator evaluator(context);
	Decryptor decryptor(context, secret_key);
	
	CKKSEncoder encoder(context);
	size_t slot_count = encoder.slot_count();
	cout << "Number of slots: " << slot_count << endl;

	vector<double> input;
	input.reserve(slot_count); // 申请空间

	double curr_point = 0;
	//static_cast<double> 将size_t 转成成double 在运算
	double step_size = 1.0 / (static_cast<double>(slot_count) - 1); // 
	for (size_t i = 0; i < slot_count; i++)
	{
		input.push_back(curr_point);
		curr_point += step_size;
	}
	cout << "Input vector: " << endl;
	print_vector(input,3,7); // 打印vector 前3 项后3项,  保留小数点后7位

	cout << "Evaluating polynomial PI*x^3 + 0.4x + 1 ..." << endl;

	Plaintext plain_coeff3, plain_coeff1, plain_coeff0;
	// 编码
	encoder.encode(3.14159265, scale, plain_coeff3);
	encoder.encode(0.4, scale, plain_coeff1);
	encoder.encode(1.0, scale, plain_coeff0);

	Plaintext x_plain;
	print_line(__LINE__);
	cout << "Encode input vectors." << endl;
	encoder.encode(input, scale, x_plain);
	// 加密
	Ciphertext x1_encrypted;
	encryptor.encrypt(x_plain, x1_encrypted);
	/*
	* 为了计算x^3，我们首先计算x^2并重新线性化。然而，scale已经现在变成了2的80次方。
	*/


	// x^2
	Ciphertext x3_encrypted;
	print_line(__LINE__);
	cout << "Compute x^2 and relinearize:" << endl;
	evaluator.square(x1_encrypted, x3_encrypted); // x3_encrypted = x1_encrypted * x1_encrypted

	evaluator.relinearize_inplace(x3_encrypted, relin_keys);

	cout << "    + Scale of x^2 before rescale: " << log2(x3_encrypted.scale()) << " bits" << endl;

	/*
	* 现在重新调节;rescale
	* 除了modulus switch 方法外，scale 减少的系数等于被转移的质数（40位质数）
	* 因此,	新的比例尺应该接近2^40。然而，scale != 2^40 :这是因为40位素数只是接近2^40。
	* 
	*/
	print_line(__LINE__);
	cout << "Rescale x^2." << endl;
	evaluator.rescale_to_next_inplace(x3_encrypted); // 重新调整scale 规模
	cout << "    + Scale of x^2 after rescale: " << log2(x3_encrypted.scale()) << " bits" << endl;

	/*
	* 现在x3_encrypted与x1_encrypted处于不同的级别
	* 这阻止了我们 x3_encrypted*x1_encrypted 来计算x^3
	* 因此通过modulus switch 链 将x1_encrypted 切换到与x3_encrypted 同一级别,
	* 但又需要计算PI* x^3  所以 我们先计算 PI*x  然后调整scale 从2^80 -> 2^40 
	* 然后在计算 Pi*x * x^2 
	* 
	*/
	print_line(__LINE__);

	// PI * x
	cout << "Compute and rescale PI*x." << endl;
	Ciphertext x1_encrypted_coeff3;
	evaluator.multiply_plain(x1_encrypted, plain_coeff3, x1_encrypted_coeff3);// x1_encrypted_coeff3 = x1_encrypted * plain_coeff3
	cout << "    + Scale of PI*x before rescale: " << log2(x1_encrypted_coeff3.scale()) << " bits" << endl;
	evaluator.rescale_to_next_inplace(x1_encrypted_coeff3);
	cout << "    + Scale of PI*x after rescale: " << log2(x1_encrypted_coeff3.scale()) << " bits" << endl;
	
	//(PI*x)*x^2.
	print_line(__LINE__);
	cout << "Compute, relinearize, and rescale (PI*x)*x^2." << endl;
	evaluator.multiply_inplace(x3_encrypted, x1_encrypted_coeff3);
	evaluator.relinearize_inplace(x3_encrypted, relin_keys);
	cout << "    + Scale of PI*x^3 before rescale: " << log2(x3_encrypted.scale()) << " bits" << endl;
	evaluator.rescale_to_next_inplace(x3_encrypted);
	cout << "    + Scale of PI*x^3 after rescale: " << log2(x3_encrypted.scale()) << " bits" << endl;

	// 0.4*x
	print_line(__LINE__);
	cout << "Compute and rescale 0.4*x." << endl;
	evaluator.multiply_plain_inplace(x1_encrypted, plain_coeff1);
	cout << "    + Scale of 0.4*x before rescale: " << log2(x1_encrypted.scale()) << " bits" << endl;
	evaluator.rescale_to_next_inplace(x1_encrypted);
	cout << "    + Scale of 0.4*x after rescale: " << log2(x1_encrypted.scale()) << " bits" << endl;

	/*
	* 现在我们希望计算这三项的和。然而,有一个严重的问题是:
	这三个术语使用的加密参数都是不同是由于模数从缩放转换而来。
	加密的加法和减法要求输入的刻度为相同，
	并且加密参数(parms_id)匹配。如果有不匹配时，求值器将抛出异常。
	*/
	cout << endl;
	print_line(__LINE__);
	cout << "Parameters used by all three terms are different." << endl;
	cout << "    + Modulus chain index for x3_encrypted: "
		<< context.get_context_data(x3_encrypted.parms_id())->chain_index() << endl;
	cout << "    + Modulus chain index for x1_encrypted: "
		<< context.get_context_data(x1_encrypted.parms_id())->chain_index() << endl;
	cout << "    + Modulus chain index for plain_coeff0: "
		<< context.get_context_data(plain_coeff0.parms_id())->chain_index() << endl;
	cout << endl;

	print_line(__LINE__);
	cout << "The exact scales of all three terms are different:" << endl;
	ios old_fmt(nullptr);
	old_fmt.copyfmt(cout);
	cout << fixed << setprecision(10);
	cout << "    + Exact scale in PI*x^3: " << x3_encrypted.scale() << endl;
	cout << "    + Exact scale in  0.4*x: " << x1_encrypted.scale() << endl;
	cout << "    + Exact scale in      1: " << plain_coeff0.scale() << endl;
	cout << endl;
	cout.copyfmt(old_fmt);


	print_line(__LINE__);
	cout << "Normalize scales to 2^40." << endl;
	x3_encrypted.scale() = pow(2.0, 40);
	x1_encrypted.scale() = pow(2.0, 40);
	/*
	* 我们还有加密参数不匹配的问题。这是很容易的通过使用modulus switching (no rescaling) 来解决
	*/
	print_line(__LINE__);
	cout << "Normalize encryption parameters to the lowest level." << endl;
	parms_id_type last_parms_id = x3_encrypted.parms_id();
	evaluator.mod_switch_to_inplace(x1_encrypted, last_parms_id);
	evaluator.mod_switch_to_inplace(plain_coeff0, last_parms_id);

	/*
	到现在这三种密文现在都是兼容的，可以进行add运算了
	*/
	print_line(__LINE__);
	cout << "Compute PI*x^3 + 0.4*x + 1." << endl;
	Ciphertext encrypted_result;
	evaluator.add(x3_encrypted, x1_encrypted, encrypted_result);
	evaluator.add_plain_inplace(encrypted_result, plain_coeff0);


	Plaintext plain_result;
	print_line(__LINE__);
	cout << "Decrypt and decode PI*x^3 + 0.4x + 1." << endl;
	cout << "    + Expected result:" << endl;
	vector<double> true_result;
	for (size_t i = 0; i < input.size(); i++)
	{
		double x = input[i];
		true_result.push_back((3.14159265 * x * x + 0.4) * x + 1);
	}
	print_vector(true_result, 3, 7);

	/*
	Decrypt, decode, and print the result.
	*/
	decryptor.decrypt(encrypted_result, plain_result);
	vector<double> result;
	encoder.decode(plain_result, result);
	cout << "    + Computed result ...... Correct." << endl;
	print_vector(result, 3, 7);
	return;
}
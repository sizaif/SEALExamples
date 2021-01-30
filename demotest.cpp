
#include <bits/stdc++.h>
#include "seal/seal.h"
#include "examples.h"
#include <iostream>
#include <fstream>


using namespace std;
using namespace seal;


void create_database(size_t slot_count) {

    double curr_point = 0;
    double step_size = 1.0 / (static_cast<double>(slot_count) - 1); // 
    ofstream out;
    out.open("database.txt", ios::in | ios::out | ios::binary | ios::trunc);
    if (out.is_open()) {
        int step = 0;
        for (size_t i = 0; i < slot_count; i++)
        {
            // 没10行一个数据
            if(step %10 == 9)
                out << curr_point << "\n";
            else {
                out << curr_point << " ";
            }
            step++;
            curr_point += step_size;
        }
        out << endl;
        out.close();
        cout << "Input vector: " << endl;
        //print_vector(v_input, 3, 7); // 打印vector 前3 项后3项,  保留小数点后7位
    }
}
vector<double> get_input(size_t slot_count) {
   
  
    vector<double> input(slot_count, 0ULL);
    //input.reserve(slot_count); // 申请空间

    ifstream in("input.txt", ios::in);
    if (in.is_open()) {
        string str;
        auto it = input.begin();
        while (getline(in, str)) {
            stringstream input_txt(str);
            string str_result;
            while (input_txt >> str_result) {
                (*it) = atof(str_result.c_str());
                it++;
                //input.push_back(atof(str_result.c_str())); // string -> double;
                
            }
        }
        in.close();
    }
    print_line(__LINE__);
    cout << " input of V: " << endl;
    print_vector(input, 5, 7); // 前5 后5 项
    print_line(__LINE__);

    
    return input;
}

vector<vector<double>> get_database(size_t slot_count) {

    vector<vector<double>> E_matrix;
    
    

    ifstream in("database.txt", ios::in);
    if (in.is_open()) {
        string str;

        while (getline(in, str)) {
            stringstream input_txt(str);
            string str_result;
            vector<double> input(slot_count,0ULL);
            auto it = input.begin();
            while (input_txt >> str_result) {
                (*it) = atof(str_result.c_str());
                it++;
                //input.push_back(atof(str_result.c_str())); // string -> double;
            }
            E_matrix.push_back(input);
        }
        in.close();
    }
    
    print_line(__LINE__);
    cout << "i.e. database of E: " << endl;
    // 输出测试
    print_vector(E_matrix[0], 5, 7);
    print_vector(E_matrix[1], 5, 7);
    print_vector(E_matrix[2], 5, 7);

    return E_matrix;
}
void test1() {

    EncryptionParameters parms(scheme_type::ckks);
    size_t poly_modulus_degree = 8192;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, { 60, 40,40, 60 }));


    SEALContext context(parms);
    print_parameters(context);
    cout << endl;

    // 密钥
    KeyGenerator keygen(context);
    auto secret_key = keygen.secret_key();
    PublicKey public_key;
    keygen.create_public_key(public_key);
    RelinKeys relin_keys;
    keygen.create_relin_keys(relin_keys);
    GaloisKeys galois_keys;
    keygen.create_galois_keys(galois_keys);

    //加密器
    Encryptor encryptor(context, public_key);
    //计算器
    Evaluator evaluator(context);
    //解密器
    Decryptor decryptor(context, secret_key);

    CKKSEncoder ckks_encoder(context);
    
    // 放大因子
    double scale = pow(2.0, 40);
    
    size_t slot_count = ckks_encoder.slot_count();
    cout << "Number of slots: " << slot_count << endl;



    double curr_point = 0;
    double step_size = 1.0 / (static_cast<double>(slot_count) - 1); // 
    //create_database(slot_count);
    vector<double> v_input = get_input(slot_count);
    vector<vector<double>> E_matrix = get_database(slot_count);
    /*
    // 写入input
    ofstream out;
    out.open("input.txt", ios::in | ios::out | ios::binary| ios::trunc);
    if (out.is_open()) {
        for (size_t i = 0; i < 10; i++)
        {
            out << curr_point << " ";
            //input.push_back(curr_point);
            curr_point += step_size;
        }
        out << endl;
        out.close();
        cout << "Input vector: " << endl;
        //print_vector(v_input, 3, 7); // 打印vector 前3 项后3项,  保留小数点后7位
    }
    */
    

    Plaintext v_plaintext;
    // v编码
    ckks_encoder.encode(v_input, scale, v_plaintext); 
    Ciphertext probe_p;
    // 加密
    encryptor.encrypt(v_plaintext, probe_p); 
    

    

    return;
}

# SEALExamples
Microsoft SEAL学习

@[TOC]



# 说明

1. `使用的HE方案是`**CKKS**

```c++
/
| Encryption parameters :
|   scheme: CKKS
|   poly_modulus_degree: 8192
|   coeff_modulus size: 200 (60 + 40 + 40 + 60) bits
|   scale: pow(2.0,40)
\

```

2. 输入数据的长度 n = 10 ,
3. 因为没有用FaceNet数据集的缘故,演示所用的测试数据来源为简单生成,[生成方式为:](#数据来源)
4. 编译平台: Visual Studio 2019
5. 所需外部环境: `seal.h`  ; ` examples.h` ； `bits/stdc++.h`
6. 待补充

# 数据来源



输入的input数据和database数据来源生成代码如下:

```c++
// slot_count = poly_modulus_degree /2  => 4096 
double curr_point = 0;
double step_size = 1.0 / (static_cast<double>(slot_count) - 1); 
ofstream out;
out.open("database.txt", ios::in | ios::out | ios::binary | ios::trunc);
if (out.is_open()) {
    int step = 0;
    for (size_t i = 0; i < slot_count; i++)
    {
        // 每10行一个数据
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
}
```

**选取的input数据如下:**

[0.984127 0.984371 0.984615 0.98486 0.985104 0.985348 0.985592 0.985836 0.986081 0.986325]

`从生成的database中最后10行中选取第6行生成`

![image-20210203124141787](https://gitee.com/sizaif/images/raw/master/img/20210203124141.png)

------

**选取的database E 数据如下:**

[0.974359 0.974603 0.974847 0.975092 0.975336 0.97558 0.975824 0.976068 0.976313 0.976557]
		[0.976801 0.977045 0.977289 0.977534 0.977778 0.978022 0.978266 0.97851 0.978755 0.978999]
		[0.979243 0.979487 0.979731 0.979976 0.98022 0.980464 0.980708 0.980952 0.981197 0.981441]
		[0.981685 0.981929 0.982173 0.982418 0.982662 0.982906 0.98315 0.983394 0.983639 0.983883]
		[0.984127 0.984371 0.984615 0.98486 0.985104 0.985348 0.985592 0.985836 0.986081 0.986325]
		[0.986569 0.986813 0.987057 0.987302 0.987546 0.98779 0.988034 0.988278 0.988523 0.988767]
		[0.989011 0.989255 0.989499 0.989744 0.989988 0.990232 0.990476 0.99072 0.990965 0.991209]
		[0.991453 0.991697 0.991941 0.992186 0.99243 0.992674 0.992918 0.993162 0.993407 0.993651]
		[0.993895 0.994139 0.994383 0.994628 0.994872 0.995116 0.99536 0.995604 0.995849 0.996093]
		[0.996337 0.996581 0.996825 0.99707 0.997314 0.997558 0.997802 0.998046 0.998291 0.998535]

------

![image-20210203124350026](https://gitee.com/sizaif/images/raw/master/img/20210203124350.png)



# 过程步骤



### 总览

1. 首先计算 p 与 E 中的 $C_{i}$ 比较分数并用 $r_{i}$表示,求最佳的 $r_{i}$, 

   ​	$\mathbf{r}_{i}=\operatorname{dist}\left(\mathbf{p}, \mathbf{c}_{i}\right) \cdot \mathbf{k}$   ; $k=\left \{ 1,0,...0 \right \} $

2. 处理完全部数据库内容后,N个单独结果的vector  $\mathbf{R}=\left[\begin{array}{c}\mathbf{r}_{1} \\ \mathbf{r}_{2} \\ \vdots \\ \mathbf{r}_{N}\end{array}\right]=\left[\begin{array}{c}\left(\mathbf{r}_{1,1}, 0, \ldots 0\right) \\ \left(\mathbf{r}_{2,1}, 0, \ldots 0\right) \\ \vdots \\ \left(\mathbf{r}_{N, 1}, 0, \ldots 0\right)\end{array}\right]$ 每个$r_{i}$是单独加密的, 可以随机打乱$r_{i}$的顺序

3. 通过将$r_{i}$移位,变成对角矩阵 例如 $\mathbf{R}=\left[\begin{array}{c}
   \left(\mathbf{r}_{1,1}, 0, \ldots 0\right) \\
   \left(0, \mathbf{r}_{2,1}, \ldots 0\right) \\
   \vdots \\
   \left(0,0, \ldots \mathbf{r}_{N, 1}\right)
   \end{array}\right]$

4. 将对角线上vector组合成新的带有与P比较分数的vector格式   i.e.  $R->\left(\mathbf{r}_{1,1}, \mathbf{r}_{2,1}, \ldots \mathbf{r}_{N, 1}\right)$

5. 将上式跟预先设定的阈值$ {t}=(t, t, \ldots t)$进行比较   形成新的vector d:  $ d = R - t $, 然后将d 传输给第三方

6. 最终将 d 进行解密决定结果(decision),并传送给客户 $ d = R - t $ ;   $\text { decision }=\left\{\begin{array}{ll}
   \text { accept } & \text { if } \exists d \in \mathbf{d}: d>0 \\
   \text { reject } & \text { if } \forall d \in \mathbf{d}: d \leq 0
   \end{array}\right. $



## 一: 将input和database中的数据分别加密获得encrypt_probe_p和 encrypt_E_matrix



**1：加密得到probe_p**

```c++
Ciphertext get_encrypt_probe(CKKSEncoder& ckks_encoder,Encryptor & encryptor, vector<double>v_input) {
    print_line(__LINE__);
    cout << "------get_encrypt_probe() begin------" << endl;

    /*
    * 加密获得probe_p;
    */
    Plaintext v_plaintext;
    // v编码
    ckks_encoder.encode(v_input, scale, v_plaintext);
    Ciphertext probe_p;
    // 加密
    encryptor.encrypt(v_plaintext, probe_p);

    print_line(__LINE__);
    cout << "------get_encrypt_probe() end------" << endl;
    return probe_p;
}
```

![image-20210203124905421](https://gitee.com/sizaif/images/raw/master/img/20210203124905.png)

将加密的probe_p解密做验证:

![image-20210203130111249](https://gitee.com/sizaif/images/raw/master/img/20210203130111.png)

------



**2：将database中的所有数据分别加密，组成矩阵E:**

```c++
vector<Ciphertext> get_encrypt_E_matrix(CKKSEncoder& ckks_encoder, Encryptor& encryptor, vector<vector<double>>E_matrix) {
    print_line(__LINE__);
    cout << "------get_encrypt_E_matrix() begin------" << endl;
    
    vector<Ciphertext> encrypt_E_matrix;
    for (auto it = E_matrix.begin(); it != E_matrix.end(); it++) {
        Plaintext plain_E_ci;
        Ciphertext encrypt_E_ci;
        ckks_encoder.encode(*it, scale, plain_E_ci);
        encryptor.encrypt(plain_E_ci, encrypt_E_ci);
        encrypt_E_matrix.push_back(encrypt_E_ci);
    }
    print_line(__LINE__);
    cout << "------get_encrypt_E_matrix() end------" << endl;

    return encrypt_E_matrix;
}
```

![image-20210203124920149](https://gitee.com/sizaif/images/raw/master/img/20210203124920.png)

**将加密的databse数据做解密验证:**

`输出前4行:`

![image-20210203130122350](https://gitee.com/sizaif/images/raw/master/img/20210203130122.png)

------

##  二: 计算   $\mathbf{r}_{i}=\operatorname{dist}\left(\mathbf{p}, \mathbf{c}_{i}\right) \cdot \mathbf{k}$

所用方式为欧拉距离：$\sum_{i=0}^{s}\left(\mathbf{c}_{i}-\mathbf{p}_{i}\right)^{2}$

分步骤:	

1. [先求$(C_{i} - P_{i})$ ；](###1：求 ${(C_{i} - P_{i})}^{2} $)

2. [再求 ${(C_{i} - P_{i})}^{2} $ ；](###1：求 ${(C_{i} - P_{i})}^{2} $)

   			3. [将得到的结果通过shift移位操作不断加到自身求得 $\sum_{i=0}^{s}\left(\mathbf{c}_{i}-\mathbf{p}_{i}\right)^{2}$；](###2:   $\sum_{i=0}^{s}\left(\mathbf{c}_{i}-\mathbf{p}_{i}\right)^{2}$)
   			4. [将结果做 $ \operatorname{dist}\left(\mathbf{p}, \mathbf{c}_{i}\right) \cdot \mathbf{k}$ 得到R；](###3: 求 $ \operatorname{dist}\left(\mathbf{p}, \mathbf{c}_{i}\right) \cdot \mathbf{k}$)

**最终R的结果样式为**:$\mathbf{R}=\left[\begin{array}{c}\mathbf{r}_{1} \\ \mathbf{r}_{2} \\ \vdots \\ \mathbf{r}_{N}\end{array}\right]=\left[\begin{array}{c}\left(\mathbf{r}_{1,1}, 0, \ldots 0\right) \\ \left(\mathbf{r}_{2,1}, 0, \ldots 0\right) \\ \vdots \\ \left(\mathbf{r}_{N, 1}, 0, \ldots 0\right)\end{array}\right]$ 



**总代码调用:**

```c++
vector<Ciphertext> get_dist(SEALContext& context,CKKSEncoder& ckks_encoder, Evaluator& evaluator, vector<Ciphertext> encrypt_E_matrix, Ciphertext probe_p,Encryptor & encryptor ,Decryptor& decryptor, RelinKeys& relin_keys,  GaloisKeys& galois_keys) {
    print_line(__LINE__);
    cout << "------get_dist() begin------" << endl;
    vector<Ciphertext> encrypt_R_matrix;

    /*
    * get (Ci - Pi)^2
    */
   
    cout << "sub & square && stored in encrypt_R_matrix: " << endl;
    vector<Ciphertext> encrypt_R_matrix_cache = get_sub_square(ckks_encoder, evaluator, decryptor,encrypt_E_matrix,probe_p, relin_keys);

    /*
    * get sum
    */
    encrypt_R_matrix = get_sum_rotate(context,ckks_encoder,evaluator,encryptor, decryptor, encrypt_R_matrix_cache,galois_keys,relin_keys);

    print_line(__LINE__);
    cout << "------get_dist() end------" << endl;
    return encrypt_R_matrix;
}
```





### 1：求 ${(C_{i} - P_{i})}^{2} $

```c++
vector<Ciphertext> get_sub_square(CKKSEncoder& ckks_encoder,Evaluator & evaluator,Decryptor & decryptor,vector<Ciphertext> encrypt_E_matrix, Ciphertext probe_p,RelinKeys & relin_keys) {
    
    print_line(__LINE__);
    cout << "------get_sub_square() begin------" << endl;
    
    vector<Ciphertext> encrypt_R_matrix;
    for (auto it = encrypt_E_matrix.begin(); it != encrypt_E_matrix.end(); it++) {

        Plaintext plain_sub_cache, plain_mult_cache;
        Ciphertext encrypt_sub_cache, encrypt_multiply_cache;
        vector<double>result_sub_cache, result_mult_cache;

        evaluator.sub(probe_p, (*it), encrypt_sub_cache);
        evaluator.relinearize_inplace(encrypt_sub_cache, relin_keys);

        evaluator.square(encrypt_sub_cache, encrypt_multiply_cache);
        
        evaluator.relinearize_inplace(encrypt_multiply_cache, relin_keys);
        evaluator.rescale_to_next_inplace(encrypt_multiply_cache);
         
        encrypt_R_matrix.push_back(encrypt_multiply_cache);

    }
    print_line(__LINE__);
    cout << "------get_sub_square() end------" << endl;
    return encrypt_R_matrix;
}
```



**解码结果验证测试：**

​	1. $(C_{i} - P_{i})$结果:

![image-20210203132236684](https://gitee.com/sizaif/images/raw/master/img/20210203132236.png)

2. ${(C_{i} - P_{i})}^{2} $结果:

   ![image-20210203133516381](https://gitee.com/sizaif/images/raw/master/img/20210203133516.png)

------

### 2:   $\sum_{i=0}^{s}\left(\mathbf{c}_{i}-\mathbf{p}_{i}\right)^{2}$

`循环遍历encrypt_R_matrix， 将密文每次移位step步后加到encrypt_sum_cache上得到最终的结果，`

`step从0到number-1`

```C++
vector<Ciphertext> get_sum_rotate(SEALContext &context,CKKSEncoder& ckks_encoder, Evaluator& evaluator,Encryptor &encryptor ,Decryptor& decryptor, vector<Ciphertext>encrypt_R_matrix,GaloisKeys & galois_keys,RelinKeys & relin_keys) {
    
    print_line(__LINE__);
    cout << "------get_sum_rotate() begin------" << endl;
    vector<Ciphertext> encrypt_RR_matrix;

    /*
    * get encryptor of vector K{1,0,0,....0}
    * begin
    */
    size_t slot_count = ckks_encoder.slot_count();
    vector<double>vector_k(slot_count, 0ULL);
    vector_k[0] = 1ULL;
    //print_vector(vector_k, 3, 13);

    Plaintext plain_vector_k;
    Ciphertext encrypt_vector_k;
    ckks_encoder.encode(vector_k, pow(2.0, 40), plain_vector_k);
    encryptor.encrypt(plain_vector_k, encrypt_vector_k);
    evaluator.mod_switch_to_next_inplace(encrypt_vector_k);
    //end

    /*
    *  Calculate begin
    */
    for (auto it = encrypt_R_matrix.begin(); it != encrypt_R_matrix.end(); it++) {

        Plaintext plain_rotated_cache, plain_sum_cache;
        Ciphertext encrypt_rotated_cache, encrypt_sum_cache;
        vector<double>result_rotated_cache, result_sum_cache;

        encrypt_sum_cache = (*it);
        /*
        * rotated & add to get sum of them
        */
        for (auto i = 0; i < number_n - 1; i++) {
            evaluator.rotate_vector(encrypt_sum_cache, 1, galois_keys, encrypt_rotated_cache);
            encrypt_sum_cache = encrypt_rotated_cache;
            evaluator.add_inplace(encrypt_sum_cache,(*it) );
            evaluator.relinearize_inplace(encrypt_sum_cache, relin_keys);

        }
        evaluator.multiply_inplace(encrypt_sum_cache, encrypt_vector_k);
        evaluator.relinearize_inplace(encrypt_sum_cache, relin_keys);
        evaluator.rescale_to_next_inplace(encrypt_sum_cache);
        encrypt_RR_matrix.push_back(encrypt_sum_cache);
    }
    /*
    *  Calculate end;
    */
    print_line(__LINE__);
    cout << "------get_sum_rotate() end------" << endl;
    return encrypt_RR_matrix;
}
```



**解码结果验证测试(部分截取):**

![image-20210203140928407](https://gitee.com/sizaif/images/raw/master/img/20210203140928.png)

------

### 3: 求 $ \operatorname{dist}\left(\mathbf{p}, \mathbf{c}_{i}\right) \cdot \mathbf{k}$

**代码内嵌在第二步求 2:   $\sum_{i=0}^{s}\left(\mathbf{c}_{i}-\mathbf{p}_{i}\right)^{2}$中**

```c++
evaluator.multiply_inplace(encrypt_sum_cache, encrypt_vector_k);
evaluator.rescale_to_next_inplace(encrypt_sum_cache);
encrypt_RR_matrix.push_back(encrypt_sum_cache);
```



解码结果验证:

<img src="https://gitee.com/sizaif/images/raw/master/img/20210203140007.png" alt="image-20210203140007458"  />



------

## 三: 将得到 R 进行移位叠加操作:

通过将$r_{i}$移位,变成对角矩阵 例如 $\mathbf{R}=\left[\begin{array}{c}
\left(\mathbf{r}_{1,1}, 0, \ldots 0\right) \\
\left(0, \mathbf{r}_{2,1}, \ldots 0\right) \\
\vdots \\
\left(0,0, \ldots \mathbf{r}_{N, 1}\right)
\end{array}\right]$



```c++
vector<Ciphertext> get_shifting_ri(SEALContext& context,CKKSEncoder& ckks_encoder,Evaluator& evaluator,vector<Ciphertext> encrypt_R_matrix, GaloisKeys& galois_keys, Decryptor& decryptor) {
    print_line(__LINE__);
    cout << "------get_shifting_ri() begin------" << endl;

    vector<Ciphertext> encrypt_RR_matrix;
    Plaintext plain_shift_cache;
    vector<double>result_shift_cache;
    
    int step = 0;
    for (auto it = encrypt_R_matrix.begin(); it != encrypt_R_matrix.end(); it++) {
        Ciphertext after_shift;
        // 右移
        evaluator.rotate_vector((*it),step, galois_keys,after_shift);
        step--;
        encrypt_RR_matrix.push_back(after_shift);
        
    }
    print_line(__LINE__);
    cout << "------get_shifting_ri() end------" << endl;
    return encrypt_RR_matrix;
}

```



**解码结果验证测试；**

`输出前10列前10行， 保留13位小数`

<img src="https://gitee.com/sizaif/images/raw/master/img/20210203162006.png" alt="image-20210203162006063" style="zoom:200%;" />



------

## 四: 将得到 $R->\left(\mathbf{r}_{1,1}, \mathbf{r}_{2,1}, \ldots \mathbf{r}_{N, 1}\right)$:

通过移位操作得到对角矩阵后，将所有的$C_{i}$ 累加起来得到$R->\left(\mathbf{r}_{1,1}, \mathbf{r}_{2,1}, \ldots \mathbf{r}_{N, 1}\right)$:



```c++
Ciphertext get_combined_R(SEALContext& context,CKKSEncoder& ckks_encoder,Evaluator& evaluator, vector<Ciphertext> encrypt_R_matrix, Encryptor& encryptor, Decryptor& decryptor, RelinKeys& relin_keys) {
    print_line(__LINE__);
    cout << "------get_combined_R() begin------" << endl;
    
    Ciphertext encrypt_R_sum_cache;

    cout << " combined together: " << endl;
    int step = 0;
    for (auto it = encrypt_R_matrix.begin(); it != encrypt_R_matrix.end(); it++) {
        
        if (step == 0)
        {
            encrypt_R_sum_cache = (*it);
            step++;
            continue;
        }
        else {
            parms_id_type last_parms_id = (*it).parms_id();
            evaluator.add_inplace(encrypt_R_sum_cache, (*it));
            evaluator.relinearize_inplace(encrypt_R_sum_cache,relin_keys);
            step++;
        }
    }

    print_line(__LINE__);
    cout << "------get_combined_R() end------" << endl;
    return encrypt_R_sum_cache;
}

```

**解密结果测试:**

![image-20210203183212079](https://gitee.com/sizaif/images/raw/master/img/20210203183212.png)

------



# 最终结果展示

==注意！==

`(因为没有用FaceNet缘故,这里给定的阈值 t 不得知，故程序只运行到将R做完对角化后并加在一起变成一个`

$R->(r1,1, r2,1, . . . rN,1).$形式

`若给定的设定的t已知; 则只需要做如下操作判定结果:`

```c++
// d = R - t
Ciphertext encrypt_T,encrypt_d;
evaluator.sub(mapping_R,encrypt_T,encrypt_d);

// *d = Dec(d)
Plaintext plain_dd_cache;
vector<double>result_dd_cache;
decryptor.decrypt(encrypt_d, plain_dd_cache);
ckks_encoder.decode(plain_dd_cache, result_dd_cache);
// judge ∃d ∈ d∗: d > 0 ? accept : reject
bool ok = 0;
auto len = result_dd_cache.size();
for (auto i = 0; i < len; i++) {
    if (result_dd_cache[i] > 0) {
        ok = 1;
        break;
    }
}
string ans = ok ? "accept" : "reject";
cout << ans << endl; //输出最后结果
```





![image-20210203183215036](https://gitee.com/sizaif/images/raw/master/img/20210203183212.png)


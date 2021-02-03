# SEALExamples
Microsoft SEAL学习
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

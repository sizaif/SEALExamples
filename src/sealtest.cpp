
#include "seal/seal.h"
#include "examples.h"
#include <iostream>
//#include "network.h"
//#include "mtcnn.h"
//#include <torch/torch.h>
//#include <torch/script.h>

#include <opencv2/opencv.hpp>
#include <opencv2/core/core.hpp>
#include <opencv2/highgui/highgui.hpp>
#include <opencv2/imgproc/imgproc.hpp>
#include <opencv2/imgcodecs/imgcodecs.hpp> 

#include "tensorflow/core/framework/graph.pb.h"
#include "tensorflow/core/framework/tensor.h"
#include "tensorflow/core/graph/default_device.h"
#include "tensorflow/core/graph/graph_def_builder.h"
#include "tensorflow/core/public/session.h"

using namespace std;
using namespace seal;
using namespace tensorflow;
using namespace cv;

using tensorflow::Tensor;
using tensorflow::Status;
int main()
{
    cout << " hello world" << endl;
    //bfv_basics();
    //example_encoders();
    //example_levels();
    //定义加密参数
    //void test1(); // 声明一下test1函数，源代码在demotest里
    //test1();
    //example_ckks_basics();
    //example_rotation();
    
    //torch::Tensor tensor = torch::rand({ 5,3 });
    // std::cout << tensor << std::endl;
    
    //torch::Tensor tensor = torch::rand({ 5,3 });
    //std::cout << tensor << std::endl;
    //return EXIT_SUCCESS;
    


    return 0;
}



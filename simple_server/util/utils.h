//
// Created by JiangKan on 2019/3/27.
//

#ifndef LINUX_UTILS_H
#define LINUX_UTILS_H

#include <iostream>
#include <string>
#include <memory>


//去除字符串两端的空格
std::string trim(std::string s);

//修改进程的名字
//std::shared_ptr<char> rename_process(const std::string& new_name);


//获取当前时间并格式化
std::string str_time();



#endif //LINUX_UTILS_H

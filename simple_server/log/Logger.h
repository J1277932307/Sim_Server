//
// Created by JiangKan on 2019/3/28.
//

#ifndef LINUX_LOGGER_H
#define LINUX_LOGGER_H

#include <string>
#include <fstream>
#include <iostream>
#include <vector>
#include <mutex>
#include "../global_value.h"

using std::ofstream;

class Logger
{
private:
    static Logger* log_ptr;
    std::string log_path;          //配置文件目录
    int level;               //配置文件中用户定义的最低日志记录级别
    ofstream fout;
    std::vector<std::string> trans_level;    //用于将enum类型的level值转换为更易读的字符串
    Logger(std::string log_path,int level);
    Logger();
public:
    static Logger* getInstance();
    ~Logger();
    bool write_to_log(log_level lev = DEBUG,int no = 0,const std::string& info = "无异常");
    static void write_to_screen(const std::string& info);
    //使用类中类释放资源
    class CG_flags
    {
    public:
        ~CG_flags()
        {
            if(Logger::log_ptr)
            {
                if(log_ptr->fout.is_open())
                    log_ptr->fout.close();
                delete Logger::log_ptr;

                Logger::log_ptr = nullptr;
            }
        }
    };




};


#endif //LINUX_LOGGER_H

//
// Created by JiangKan on 2019/4/20.
//

//
// Created by JiangKan on 2019/3/28.
//

#include <unistd.h>
#include "Logger.h"
#include "../util/utils.h"
#include "../configurer/Configurer.h"
#include <mutex>


using namespace std;

std::once_flag flag;
Logger *Logger::log_ptr = nullptr;

Logger::Logger(string log_path, int level) : log_path(log_path), level(level)
{

    fout.open(log_path, ios_base::out | ios_base::app);
    trans_level = {"stderr", "emerg", "alert", "crit", "err", "warn", "notice", "info", "debug"};

}

Logger *Logger::getInstance()
{

//    call_once(flag,[](){
//        Configurer* configurer = Configurer::getInstance();
//        log_ptr = new Logger(configurer->get_config_by_name("log_path"),std::stoi(configurer->get_config_by_name("log_level")));
//        cout << "获取到了log的文件的地址：" << log_ptr->log_path <<endl;
//        static CG_flags cg;
//    });
    if (log_ptr == nullptr)
    {
        Configurer *configurer = Configurer::getInstance();
        log_ptr = new Logger(configurer->get_config_by_name("log_path"),
                             std::stoi(configurer->get_config_by_name("log_level")));
        cout << "获取到了log的文件的地址：" << log_ptr->log_path << endl;
        static CG_flags cg;
    }
    return log_ptr;
}

Logger::Logger() {};

Logger::~Logger()
{
}


bool Logger::write_to_log(log_level lev, int no, const std::string &info)
{
    //首先对比低日志记录级别和我们传入的日志级别的优先级大小，传入级别的优先级高于或等于默认优先级，则记录(数值越小，优先级越高)
//    if(lev > level)
//        return false;

    if (!fout.is_open())
    {
        Logger::write_to_screen("日志文件没有打开");
        return false;
    }
    fout << str_time() << " " << " [" << trans_level[lev] << "] " << " 进程ID：" << getpid() << " > " << info << " ("
         << "errno:" << no << "," << strerror(no) << ")" << endl;

    return true;


}

//向控制台中写输出，主要用在进程变成守护进程后，无法将信息输出到控制台的情况下
void Logger::write_to_screen( const std::string &info)
{


    write(STDERR_FILENO,info.c_str(),info.length());
}

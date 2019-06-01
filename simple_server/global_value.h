//
// Created by JiangKan on 2019/4/14.
//

#ifndef LINUX_GLOBAL_VALUE_H
#define LINUX_GLOBAL_VALUE_H

#include <cstring>
#include "socket/LogicSocket.h"
#include "thread/Thread.h"



//引用的全局变量
extern int exitcode;

//日志警告级别
enum log_level
{
    STDERR,  //极其严重的错误，不再写入日志文件，而是直接打印到控制台，让用户看到
    EMERG,   //紧急错误
    ALERT,   //警戒
    CRIT,    //严重
    ERR,     //错误
    WARN,    //警告
    NOTICE,  //注意
    INFO,    //信息
    DEBUG    //调试
};

//定义进程的类别，分别为master进程和worker进程
enum PROCESS_TYPE{PROCESS_MASTER,PROCESS_WORKER};




extern int process_type;    //表示当前进程的类型:master或worker
extern pid_t pid;           //表示当前进程的pid
extern pid_t parent_pid;    //表示当前进程的父进程pid
extern int is_deamon;


extern int size_of_argv;
extern int size_of_environ;

extern int g_stop_pro;

extern LogicSocket glo_socket;
extern Thread glo_thread_pool;   //全局线程池对象


#endif //LINUX_GLOBAL_VALUE_H


#include <iostream>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <cstring>
#include "util/utils.h"
#include "signal/Signal.h"
#include "process/Process.h"
//#include "thread/Thread.h"
#include "socket/LogicSocket.h"
#include "crc/CRC32.h"
#include "memory/Memory.h"
#include "log/Logger.h"
#include "configurer/Configurer.h"



using namespace std;


//进程相关
int process_type;    //表示当前进程的类型:master或worker
pid_t pid;           //表示当前进程的pid
pid_t parent_pid;    //表示当前进程的父进程pid
int is_deamon;       //标志是否启用了守护进程
int exitcode;

int size_of_argv = 0;     //参数列表中参数总长度
int size_of_environ = 0;  //环境变量的总长度

int g_stop_pro = 0;       //全局程序退出标志位

Thread glo_thread_pool;   //全局线程池对象
LogicSocket glo_socket;   //全局Socket对象



int main(int argc, char *argv[])
{


    for (int i = 0; i < argc; ++i)
    {
        size_of_argv += strlen(argv[i]) + 1;
    }
    for (int i = 0; environ[i]; ++i)
    {
        size_of_environ += strlen(environ[i]) + 1;
    }





    //把单例类先初始化一次，在单例类中就不必进行多线程安全性的考量
    Configurer *config = Configurer::getInstance();  //初始化配置文件类，首先加载配置文件，配置文件加载不到，后续没必要继续
    Logger::getInstance();    //初始化日志类
    Memory::getInstance();    //初始化内存类
    CRC32::getInstance();     //初始化crc校验类

    //初始化信号
    Signal signal;
    if (signal.init_signals() != 0)
    {
        exitcode = 1;
        exit(exitcode);
    }

    if(!glo_socket.initialize())  //连接初始化
    {
        exitcode = 1;
        exit(exitcode);
    }

    //创建进程类
    Process process(argc, argv);

    //转移进程的环境变量
    shared_ptr<char> new_environ_ptr(process.process_move_environment_variable().get(), [](char *p) { delete[] p; });
    process_type = PROCESS_MASTER;

    //获取当前进程的进程ID
    pid = getpid();

    //获取当前进程的父进程ID
    parent_pid = getppid();

    //守护进程标志位
    is_deamon = 0;


    //配置文件中没有与守护进程相关的选项，则结束进程
    if (config->get_config_by_name("deamon") != "1")
    {
        cout << "无法创建守护进程，进程结束" << endl;
        return -1;
    }


    //创建守护进程
    int create_deamon = process.deamon();

    //创建守护进程失败，直接终止进程就完了
    if (create_deamon == -1)
    {
        exitcode = -1;
        exit(exitcode);
    }
    if (create_deamon == 1)
    {
        //这里是原始的父进程，我们在这里终止原始父进程即可
        //这里可能需要考虑释放资源的问题，其他地方我们用了智能指针和单例类(自行释放)，后续我们再考虑是否其他还需要释放资源的问题
        exitcode = 0;
        exit(exitcode);
    }

    //走到这里的已经是由子进程升级的守护进程啦
    // 设置守护进程标志
    is_deamon = 1;




    /*
     * 进程开始正式工作，包含子进程的创建与初始化等
    */
    process.master_process();


    return 0;

}

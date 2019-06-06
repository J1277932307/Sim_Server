//
// Created by JiangKan on 2019/3/30.
//

#include <unistd.h>
#include <iostream>
//#include "../global_value.h"
#include <sys/stat.h>
#include <sys/fcntl.h>
#include "Process.h"
#include "../log/Logger.h"
#include "../configurer/Configurer.h"

using namespace std;


//初始化进程的的相关参数
Process::Process(int argc_main, char **argv_main) : argc_p(argc_main), argv_p(argv_main)
{
    p_size_of_argv = size_of_argv;
    P_size_of_environ = size_of_environ;

}

/*Process::Process()
{

}*/
shared_ptr<char> Process::process_move_environment_variable()
{
    //给新的进程环境变量分配空间，shared_ptr需要自动配置删除数组的删除器
    shared_ptr<char> new_environ_ptr(new char[size_of_environ], [](char *p) { delete[] p; });
    //获取智能指针内部的原生指针，用于递加遍历
    char *ptr = new_environ_ptr.get();
    //将新分配的内存设置为空
    memset(ptr, 0, size_of_environ);
    //遍历环境变量，并将其值逐个放在新分配的内存中，并将environ[i]的指针指向新的内存地址
    for (int i = 0; environ[i]; ++i)
    {
        size_t size = strlen(environ[i]) + 1;
        strcpy(ptr, environ[i]);
        environ[i] = ptr;        //将environ[i]的指针指向新的内存地址
        ptr += size;           //指针向前步进size大小
    }

    return new_environ_ptr;
}


//创建守护进程
int Process::deamon()
{
    Logger *logger = Logger::getInstance();
    switch (fork())
    {
        case -1:
            logger->write_to_log(EMERG, errno, "创建守护进程时，fork子进程失败");
            return -1;

        case 0:
            //这里是新创建的子进程，它将作为将来的守护进程，而其父进程，我们将让其关闭某些资源后消亡
            //直接跳出循环，执行下面的语句
            break;

        default:
            //原始的父进程会走到这里来，我们只需return父进程，然后在主流程中释放为父进程分配的资源，然后终止
            //也就是说，这个函数中接下来的流程，没有这个原始父进程参与
            return 1;
    }
    //设置子进程的父进程ID为原始父进程的ID
    parent_pid = pid;
    //获取子进程的ID
    pid = getpid();

    //当进程是会话组长时setsid()调用失败。但我们fork出子进程的过程已经保证进程不是会话组长。
    // setsid()调用成功后，子进程成为新的会话组长和新的进程组长，并与原来的登录会话和进程组脱离。由于会话过程对控制终端的独占性，进程同时与控制终端脱离。
    if (setsid() == -1)
    {
        //调用失败则记录日志并返回
        logger->write_to_log(EMERG, errno, "创建守护进程时，调用setsid失败");
        return -1;
    }

    //设置umask,此进程创建文件时不屏蔽任何权限
    umask(0);

    //守护进程不能将信息发送到终端，所以将其标准输入，输出，都重定位到/dev/null。注意，！！！！！在windows上面运行测试时可能会出问题这里
    int fd = open("/dev/null", O_RDWR);
    if (fd == -1)
    {
        logger->write_to_log(EMERG, errno, "创建守护进程时，重定位守护进程标准输入输出出错，open(/dev/null)返回错误");
        return -1;

    }
    //重定位标准输入
    if (dup2(fd, STDIN_FILENO) == -1)
    {
        logger->write_to_log(EMERG, errno, "创建守护进程时，重定位守护进程标准输入失败");
        return -1;
    }
    if (dup2(fd, STDOUT_FILENO) == -1)
    {
        logger->write_to_log(EMERG, errno, "创建守护进程时，重定位守护进程标准输出失败");
        return -1;
    }
    if (fd > STDERR_FILENO)
    {
        //关闭守护进程多余的文件描述符
        if (close(fd) == -1)
        {
            logger->write_to_log(EMERG, errno, "创建守护进程时，关闭冗杂文件描述符失败");
            return -1;
        }
    }


    return 0;


}


//移动进程的环境变量


//修改进程的名字
bool Process::process_rename(const string process_name)
{
    //获取传入的进程名的长度
    size_t name_length = process_name.length();

    //获取原始进程参数列表的总长度+环境变量的总长度的总和
    size_t sum_argv_env = size_of_argv + size_of_environ;

    if (name_length >= sum_argv_env)
    {
        Logger *logger = Logger::getInstance();
        logger->write_to_log(NOTICE, 0, "由于给定名称过长，进程重命名失败");
        return false;
    }
    //将进程的argv的第二项置零，方便以后判断
    argv_p[1] = nullptr;
    char *ptmp = argv_p[0];

    //命名进程
    strcpy(ptmp, process_name.c_str());
    ptmp += name_length;

    //将剩余空间置0
    size_t spare_space = sum_argv_env - name_length;
    memset(ptmp, 0, spare_space);


    return true;
}

void Process::master_process()
{
    //首先定义屏蔽信号，防止信号干扰
    //定义一个信号集，并清空它
    sigset_t set;
    sigemptyset(&set);

    //记录日志
    Logger *logger = Logger::getInstance();

    //往信号集里放置需要屏蔽的信号
    sigaddset(&set, SIGCHLD);     //子进程状态改变
    sigaddset(&set, SIGALRM);     //定时器超时
    sigaddset(&set, SIGIO);       //异步I/O
    sigaddset(&set, SIGINT);      //终端中断符
    sigaddset(&set, SIGHUP);      //连接断开
    sigaddset(&set, SIGUSR1);     //用户定义信号
    sigaddset(&set, SIGUSR2);     //用户定义信号
    sigaddset(&set, SIGWINCH);    //终端窗口大小改变
    sigaddset(&set, SIGTERM);     //终止
    sigaddset(&set, SIGQUIT);     //终端退出符
    //后续如果有需要添加的信号，可以继续写

    //设置屏蔽
    if (sigprocmask(SIG_BLOCK, &set, nullptr) == -1)
    {
        //如果出错则记录日志

        logger->write_to_log(ALERT, errno, "在master_process中调用sigprocmask出错");
    }
    //即使调用sigprocmask出错，我们的流程还是继续往下走

    //给主进程设置进程名
    string process_name = "master process ";
    for (int i = 0; i < argc_p; ++i)
    {
        process_name += argv_p[i];
    }

    //给进程改名
    this->process_rename(process_name);

    //从配置文件中读取worker进程的数量
    Configurer *configurer = Configurer::getInstance();
    int worker_numer = std::stoi(configurer->get_config_by_name("worker_process"));

    //开始创建子进程
    this->create_worker_process(worker_numer);

    //创建子进程后，父进程将走下来，而子进程不会走下来了
    //清空父进程的信号屏蔽集合，使父进程可以接受信号
    sigemptyset(&set);


    //接下来父进程将在一个死循环中循环，一直到整个程序结束
    for (;;)
    {



        //ofstream out("z://test.txt", ios_base::app);

        //使用sigsuspend将父进程阻塞到这里，等待一个信号，此时进程是挂起的，不占用cpu时间，只有收到信号才会被唤醒
        sigsuspend(&set);


        //下面以后再补充

    }

    return;


}

void Process::create_worker_process(int thread_nums)
{
    for (int i = 0; i < thread_nums; ++i)
    {
        this->spawn_worker_process(i);
    }
}

int Process::spawn_worker_process(int thread_nums)
{
    Logger *logger = Logger::getInstance();
    pid_t pid_l;
    pid_l = fork();
    switch (pid_l)
    {

        case -1:
            //产生子进程失败
            char str_format[128];
            sprintf(str_format,"spawn_worker_process创建第%d个子进程失败",thread_nums);
            logger->write_to_log(ALERT, errno,string(str_format));
            return -1;

        case 0:     //pid等于零，说明子进程运行到这里，那么子进程就会在这里循环，不会再出去了
            parent_pid = pid;
            pid = getpid();

            //子进程将在这里循环
            this->worker_process(thread_nums);
            break;

            //这里应该是父进程，直接跳出，往下面走
        default:
            break;


    }

    return pid_l;
}

void Process::worker_process(int t_nums)
{

    //初始化worker进程
    this->init_worker_process(t_nums, string("worker process"));

    //写一个死循环，以后worker就在这个里面处理业务
    for (;;)
    {

        glo_socket.epoll_process(-1);
        glo_socket.print_Server_Info();

    }
    //如果能从这个死循环出来,释放资源
    glo_thread_pool.stop_All();
    glo_socket.shutdown_sub_process();


    return;

}

void Process::init_worker_process(int t_nums, string worker_name)
{
    Logger *logger = Logger::getInstance();

    //给worker进程改名
    this->process_rename(worker_name);
    //设置当前的进程类型为worker类型
    process_type = PROCESS_WORKER;

    //这里主要是解除从主进程继承过来的屏蔽信号集
    sigset_t set;
    sigemptyset(&set);
    if (sigprocmask(SIG_SETMASK, &set, nullptr) == -1)
    {
        char str_format[128];
        sprintf(str_format,"spawn_worker_process创建第%d个子进程失败",t_nums);

        logger->write_to_log(ALERT, errno, str_format);
    }



    //创建线程池
    Configurer* config = Configurer::getInstance();
    int thread_nums = std::stoi(config->get_config_by_name("worker_thread"));
    if(!glo_thread_pool.create_pool(thread_nums))
    {
        //线程池创建失败，强制退出，资源由系统回收
        exit(-2);
    }

    //子进程socket初始部分成员变量
    if(!glo_socket.initialize_sub_process())
    {
        //子进程socket初始化失败创建失败，强制退出，资源由系统回收
        exit(-2);
    }

    //epoll初始化
    glo_socket.epoll_init();






    //将成功的喜悦写入日志当中
    char str_format[286];
    sprintf(str_format, "%s %d 启动并开始运行......!", worker_name.c_str(), pid);
    logger->write_to_log(NOTICE, 0, string(str_format));


    //将来再扩充代码

}


//
// Created by JiangKan on 2019/3/30.
//

#include <cstring>
#include <wait.h>
#include "../log/Logger.h"
#include "Signal.h"
#include "../global_value.h"

//信号处理函数
void sig_def::signal_handler(int signo,siginfo_t* siginfo,void *ucontext)
{
//    std::cout << "信号来啦~~~~"<<std::endl;
    Signal sig;
    string action = "";
    //获取Signal类中的相关信号
    const vector<signal_t> sig_c = sig.get_sig_container();
    auto begin = sig_c.begin();
    for(;begin != sig_c.end();++begin)
    {
        if(begin->signo == signo)
        {
            //如果相关信号我们定义了处理,则跳出循环体，开始执行处理语句
            break;
        }
    }
    if(process_type == PROCESS_MASTER)
    {
        //如果是master进程，我在这里有相应的处理方式
        switch (signo)
        {
            case SIGHUP:
                std::cout << "this is a test" <<std::endl;
                break;
            case SIGINT:
                std::cout << "this is SIGINT" <<std::endl;
                break;
        }

    }else if(process_type == PROCESS_WORKER )
    {
        //如果是worker进程，我们在这里进行相应的处理
    }else
    {
        //其他进程，在这里进程处理，这里暂时想不到有什么其他进程了，先写上的，后续再看看

    }

    if(siginfo && siginfo->si_pid)
    {
        //如果能获取到发送信号的进程ID，则在日志中记录此ID;
        //使用sprintf()格式化字符串
        char str_format[128];
        sprintf(str_format,"signal %d (%s) received from %d%s",signo,begin->signame.c_str(),int(siginfo->si_pid),action.c_str());

        Logger* logger = Logger::getInstance();
        logger->write_to_log(NOTICE,0,string(str_format));


    }
    else
    {
        //如果能获取不到发送信号的进程ID，则在日志中不必记录此ID;
        char str_format[128];
        sprintf(str_format,"signal %d (%s) receive %s",signo,begin->signame.c_str(),action.c_str());

        Logger* logger = Logger::getInstance();
        logger->write_to_log(NOTICE,0,string(str_format));
    }

    //如果是子进程终止信号，我们还要获取子进程的终止信号并释放资源
    if(signo == SIGCHLD)
    {
        sig.get_process_status();
    }




}

Signal::Signal()
{
    sig_container = {
            {SIGHUP,  "SIGHUB",          signal_handler},
            {SIGINT,  "SIGINT",          signal_handler},
            {SIGTERM, "SIGTERM",         signal_handler},
            {SIGCHLD, "SIGCHLD",         signal_handler},
            {SIGQUIT, "SIGQUIT",         signal_handler},
            {SIGIO,   "SIGIO",           signal_handler},
            {SIGSYS,  "SIGSYS, SIG_IGN", nullptr}
            //以后有新的信号需要加入，再添加就可以了
    };
}


int Signal::init_signals()
{

    struct sigaction sa;

    for(auto begin = sig_container.begin();begin != sig_container.end();++begin)
    {
        memset(&sa,0, sizeof(struct sigaction));

        //构造sa
        if(begin->handler)
        {
            sa.sa_sigaction = begin->handler;
            sa.sa_flags = SA_SIGINFO;
        } else
        {
            //信号的处理函数为空时，，忽略此信号
            sa.sa_handler = SIG_IGN;
        }
        //sigaction的handler和flags赋值完成，下面开始清空sa的信号屏蔽集,不阻塞任何信号

        sigemptyset(&sa.sa_mask);
        if(sigaction(begin->signo,&sa, nullptr) == -1)
        {
            //如果设置信号处理程序出错，则写入日志当中
            //首先使用sprintf()格式化字符串
            char str_format[60];
            sprintf(str_format,"sigaction(%s) failed",begin->signame.c_str());
            Logger* log = Logger::getInstance();
            log->write_to_log(EMERG,errno,string(str_format));
            return -1;

        } else
        {
            //信号处理注册完毕，其实什么也不用管，这里只是看一下是否正常
            std::cout << "信号成功搞定:"<< begin->signame <<std::endl;
        }

    }
    return 0;
}
const vector<signal_t>& Signal::get_sig_container()
{
    return sig_container;
}


//获取子进程终止状态
void Signal::get_process_status()
{
    pid_t pid;
    int status;   //用于获取子进程终止时的状态
    int err;

    //不知道这个One有什么用，具说nginx这部分源码也定义了一个，先定义一下
    int one = 0;

    while(true)
    {
        //-1表示等待所有子进程
        pid = waitpid(-1,&status,WNOHANG);      //WNOHANG表示不阻塞，不管读不读得到都返回，一般会读到的，因为只有子进程终止的信号，才会执行到这里

        if(pid == 0)            //如果pid == 0，代表子进程正在执行当中，但只有子进程终止时才会运行到这里，所以这里意义不大
        {
            return;
        }
        if(pid == -1)     //pid == -1表示waitpid运行出现错误，记录日志;
        {
            err = errno;
            if(err == EINTR)  //如果错误代码表示，是被其他信号调用打断了waitpid()的调用，则continue，重新再调用一次
            {
                continue;
            }
            if(err == ECHILD && one)       //one在下面将会被置1，表示，如果没有子进程，且已经走过一次这里的流程的话，跳出
            {
                return;
            }
            if(err == ECHILD)      //表示没有子进程，记录日志并跳出
            {
                Logger* logger = Logger::getInstance();
                logger->write_to_log(INFO,err,"waitpid() failed!");
                return;
            }
            //无论前面记录没记录，这里最终记录一次日志
            Logger* logger = Logger::getInstance();
            logger->write_to_log(ALERT,err,"waitpid() failed!");

        }
        one = 1;

        //获取子进程异常终止时的状态，使用WTERMSIG获取使子进程异常终止的信号编号
        if(WTERMSIG(status))
        {
            char str_format[128];
            sprintf(str_format,"pid = %d exited on signal %d!",pid,WTERMSIG(status));
            Logger* logger = Logger::getInstance();
            logger->write_to_log(ALERT,0,string(str_format));
        } else
        {
            char str_format[128];
            sprintf(str_format,"pid = %d exited on signal %d!",WEXITSTATUS(status));      //WEXITSTATUS获取子进程传送给exit或_exit参数的低8位
            Logger* logger = Logger::getInstance();
            logger->write_to_log(ALERT,0,string(str_format));
        }
    }

    return;

}




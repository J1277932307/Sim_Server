//
// Created by JiangKan on 2019/3/30.
//

#ifndef LINUX_SIGNAL_H
#define LINUX_SIGNAL_H

#include <string>
#include <csignal>
#include <vector>


using std::string;
using std::vector;

//使用命名空间，定义以下变量的可见性
namespace sig_def
{
    //定义一个信号结构体
    struct signal_t
    {
        int signo;  //信号值
        string signame;   //信号的名字
        //信号处理的函数的指针形式
        void (*handler)(int signo,siginfo_t *siginfo,void *ucontext);
    };
    //定义信号处理函数
    void signal_handler(int signo,siginfo_t* siginfo,void *ucontext);



}


using namespace sig_def;
class Signal
{

private:
    vector<signal_t> sig_container;

public:
    Signal();
    int init_signals();
    const vector<signal_t>& get_sig_container();

    //这个函数的功能是获取子进程的终止状态，但是否放在这里还是放在进程管理类中，需要后续思考
    void get_process_status();

};


#endif //LINUX_SIGNAL_H

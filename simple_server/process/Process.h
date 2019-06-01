//
// Created by JiangKan on 2019/3/30.
//

#ifndef LINUX_PROCESS_H
#define LINUX_PROCESS_H

#include <memory>
#include <string>
#include <signal.h>



using std::shared_ptr;
using std::string;


class Process
{
private:
    int argc_p;              //保存进程的argc
    char** argv_p;           //获取进程的argv
    size_t p_size_of_argv;     //进程命令行参数的长度
    size_t P_size_of_environ;  //进程系统分配的环境变量的长度



public:
    Process(int argc_p, char *argv_p[]);
//    Process();
    //创建守护进程
    int deamon();

    //将进程的环境变量搬家，给进程重新命令腾地方
    shared_ptr<char> process_move_environment_variable();

    //给进程换个名字
    bool process_rename(const string process_name);

    //主进程在这个函数里循环
    void master_process();

    //创建子进程
    void create_worker_process(int thread_nums);
    void worker_process(int t_nums);
    void init_worker_process(int t_nums,string worker_name);
    int spawn_worker_process(int t);






};


#endif //LINUX_PROCESS_H

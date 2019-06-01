//
// Created by JiangKan on 2019/4/29.
//

#ifndef SIM_SERVER_LOGICSOCKET_H
#define SIM_SERVER_LOGICSOCKET_H


#include "Socket.h"

/*
 *我们引用子类的目的？
 *   这个子类用于拓展一些经常变动的业务或是需要大量重复的功能类似但又没法重载的函数
 *   父类主要写一些框架性，不常用变动的函数或功能
*/

class LogicSocket:public Socket
{
public:
    //需要拓展的业务逻辑函数
    bool handler_Register(connection_pool* pConn,MSG_HEADER* p_MsgHeader,char* p_Pkg_Body,unsigned short Pkg_body_len);  //注册函数
    bool handler_Login(connection_pool* pConn,MSG_HEADER* p_MsgHeader,char* p_Pkg_Body,unsigned short Pkg_body_len);     //登录函数
    bool handler_Ping(connection_pool* pConn,MSG_HEADER* p_MsgHeader,char* p_Pkg_Body,unsigned short Pkg_body_len);    //心跳包函数

    LogicSocket();
    virtual ~LogicSocket();
    virtual bool initialize();
    virtual void thread_recv_proc_func(char* msgbuf);
    virtual void ping_timeout_checking(MSG_HEADER* p_msg_header,time_t cut_time);
    void send_Ping_to_Client(MSG_HEADER* p_msg_header,unsigned short msgCode);

};


#endif //SIM_SERVER_LOGICSOCKET_H

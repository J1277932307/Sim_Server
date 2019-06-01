//
// Created by JiangKan on 2019/4/29.
//

#include "LogicSocket.h"
#include "../crc/CRC32.h"
#include "common_struct.h"
#include "../memory/Memory.h"
//#include "../configurer/Configurer.h"
#include "../log/Logger.h"
#include <cstring>

typedef bool (LogicSocket::*handler)(connection_pool* pConn,MSG_HEADER* p_MsgHeader,char* p_Pkg_Body,unsigned short Pkg_body_len);

//保存操作函数的数组，其中函数所有位置就是函数对应的操作码
static const handler statusHandler[] =
        {
                &LogicSocket::handler_Ping,       //位置[0]，心跳包处理函数
                nullptr,                          //位置[1]，暂无操作函数
                nullptr,                          //位置[2]，暂无操作函数
                nullptr,                          //位置[3]，暂无操作函数
                nullptr,                          //位置[4]，暂无操作函数
                &LogicSocket::handler_Register,   //位置[5],具体实现的注册函数
                &LogicSocket::handler_Login       //位置[6]具体实现的登录函数



                //如果以后有业务需要，可以再拓展
        };

const int TOTAL_COMMANDS = sizeof(statusHandler) /sizeof(handler);

LogicSocket::LogicSocket() {}
LogicSocket::~LogicSocket() {}

bool LogicSocket::initialize()
{
    bool parent_init = Socket::initialize();
    return parent_init;
}

//处理收到的消息包:消息头 + 包头 + 包体
void LogicSocket::thread_recv_proc_func(char *msgbuf)
{
    MSG_HEADER* p_msg_header = (MSG_HEADER*)msgbuf;
    PKG_HEADER* p_pkg_header = (PKG_HEADER*)(msgbuf+msg_header_len);
    char* p_pkg_body;   //指向包体
    unsigned short pkglen = ntohs(p_pkg_header->pkg_len);

    if(pkg_header_len == pkglen)
    {
        //没有包体，只有包头的包
        if(p_pkg_header->CRC32 != 0) //只有包头的包，crc给0
        {
            return;  //如果不是0，直接丢弃
        }
        p_pkg_body = nullptr;
    } else
    {
        //有包体
        p_pkg_header->CRC32 = ntohl(p_pkg_header->CRC32);
         p_pkg_body = (msgbuf+msg_header_len+pkg_header_len); //指针跳过消息头，包头，指向包体
        int cal_crc = CRC32::getInstance()->get_CRC((unsigned char*)p_pkg_body,pkglen-pkg_header_len);  //计算纯包体的crc32值

        if(cal_crc != p_pkg_header->CRC32)
        {
            return;  //直接丢弃，日志都不用打印到屏幕
        }
    }
    //包校验成功，走下来
    unsigned short msg_code = ntohs(p_pkg_header->msg_code);   //获取消息码
    connection_pool* p_Conn = p_msg_header->conn_pool;

    if(p_Conn->current_sequence != p_msg_header->cur_sequence)   //验证包是否有效
    {
        //如果从收到客户端发送来的包，到服务器分配一个线程池中的线程处理该包的过程中，客户端断开了，那显然，这种收到的包我们就不必处理了
        return;  //不处理
    }

    //判断消息码是正确的，防止客户端恶意侵害我们服务器，发送一个不在我们服务器处理范围内的消息码
    if(msg_code >= TOTAL_COMMANDS)
    {
        return; //丢弃不处理
    }

    //能走下来，说明是个正常包
    //如果没有对应的处理函数
    if(statusHandler[msg_code] == nullptr)
    {
        //丢弃此包
        return;
    }
    //走下来，一切正常，开始处理环节
    (this->*statusHandler[msg_code])(p_Conn,p_msg_header,p_pkg_body,pkglen-pkg_header_len);

}


//下面是处理各种业务逻辑的函数，注意，业务逻辑极具拓展性，可能会在以后频繁改动
bool LogicSocket::handler_Register(connection_pool *pConn, MSG_HEADER *p_MsgHeader, char *p_Pkg_Body,unsigned short Pkg_body_len)
{
    //判断包的合法性
    if(p_Pkg_Body == nullptr)  //具体看客户端服务器约定，如果约定这个命令[msgCode]必须带包体，那么如果不带包体，就认为是恶意包，直接不处理
    {
        //在注册命令中，我们是需要包体的
        return false;
    }
    int recv_len = sizeof(STRUCT_REGISTER);

    if(recv_len != Pkg_body_len)  //发送过来的结构大小不对，认为是恶意包，不处理
        return false;

    /*
     * 对于同一个用户，可能同时发送来多个请求过来，造成多个线程同时为该用户服务
     * 比如以网游为例，用户要在商店中买A物品，又买B物品，而用户的钱 只够买A或者B，不够同时买A和B呢？
     * 那如果用户发送购买命令过来买了一次A，又买了一次B，如果是两个线程来执行同一个用户的这两次不同的购买命令，很可能造成这个用户购买成功了 A，又购买成功了 B
     * 所以，为了稳妥起见，针对某个用户的命令，我们一般都要互斥,我们需要增加临界的变量于connection_pool结构中
     */
    std::lock_guard<std::mutex> lock(pConn->logic_mutex);  //凡是和本连接的操作都互斥，保证同一时间只处理一个业务
    STRUCT_REGISTER* p_recvInfo = (STRUCT_REGISTER*)p_Pkg_Body;
    p_recvInfo->code = ntohl(p_recvInfo->code);

    //调整边界，防止恶意包越界
    p_recvInfo->useranme[sizeof(p_recvInfo->useranme)-1] = '\0';
    p_recvInfo->password[sizeof(p_recvInfo->password) - 1] = '\0';



    PKG_HEADER* p_pkgHeader;
    Memory* memory = Memory::getInstance();
    CRC32 *p_crc = CRC32::getInstance();
    int sendlen = sizeof(STRUCT_REGISTER);

    char* p_sendbuf = (char*)memory->allocMemory(msg_header_len+pkg_header_len+sendlen,false);

    //填充消息头
    memcpy(p_sendbuf,p_MsgHeader,msg_header_len);

    p_pkgHeader = (PKG_HEADER*)(p_sendbuf+msg_header_len);
    p_pkgHeader->msg_code = htons(CMD_REDISTER);
    p_pkgHeader->pkg_len = htons(pkg_header_len+sendlen);

    //填充包体
    STRUCT_REGISTER* p_sendInfo = (STRUCT_REGISTER*)(p_sendbuf + msg_header_len +pkg_header_len);

    //这里根据需要，填充要发回给客户端的内容，int类型要使用htonl()转，short类型要使用htons()转

    strcpy(p_sendInfo->password,"123");
    strcpy(p_sendInfo->useranme,"注册成功");
    p_sendInfo->code = htonl(6);


    //包体全部确认之后
    p_pkgHeader->CRC32 = p_crc->get_CRC((unsigned char*)p_sendInfo,sendlen);
    p_pkgHeader->CRC32 = htonl(p_pkgHeader->CRC32);

    //把待发送包放入待发送队列当中
    put_to_msg_Queue(p_sendbuf);

    return true;

}
bool LogicSocket::handler_Login(connection_pool *pConn, MSG_HEADER *p_MsgHeader, char *p_Pkg_Body,unsigned short Pkg_body_len)
{
    Logger::write_to_screen("执行了LogicSocket::handler_Login()!");
    return true;
}

//心跳包处理函数
bool LogicSocket::handler_Ping(connection_pool *pConn, MSG_HEADER *p_MsgHeader, char *p_Pkg_Body,unsigned short Pkg_body_len)
{
    if(Pkg_body_len != 0)  //心跳包只有包头，没有包体，如果有包体则认为是非法包，丢弃
        return false;
    std::lock_guard<std::mutex> lock(pConn->logic_mutex);  //用户可能发过来连续的N个命令，使用互斥量保证命令的有序处理
    pConn->lastPing_time = time(nullptr);
    send_Ping_to_Client(p_MsgHeader,CMD_PING);
    Logger::write_to_screen("成功收到心跳包并返回结果！");
    return true;

}

//向客户端发送心跳包，心跳包只有包头，没有包体
void LogicSocket::send_Ping_to_Client(MSG_HEADER *p_msg_header, unsigned short msgCode)
{
    Memory* p_memeory = Memory::getInstance();
    char* p_sendbuf = (char*)p_memeory->allocMemory(msg_header_len+pkg_header_len,false);
    char* p_tmpbuf = p_sendbuf;

    memcpy(p_tmpbuf,p_msg_header,msg_header_len);
    p_tmpbuf += msg_header_len;

    PKG_HEADER* p_pkg_header = (PKG_HEADER*)p_tmpbuf;
    p_pkg_header->msg_code = htons(msgCode);
    p_pkg_header->pkg_len = htons(pkg_header_len);
    p_pkg_header->CRC32 = 0;

    //将消息放入待发送队列，等候发送
    put_to_msg_Queue(p_sendbuf);
}

//心跳包检测时间到，该去检测心跳包是否超时的事宜
void LogicSocket::ping_timeout_checking(MSG_HEADER *p_msg_header, time_t cut_time)
{
    Memory* memory = Memory::getInstance();
    if(p_msg_header->cur_sequence == p_msg_header->conn_pool->current_sequence)  //连接没断开过
    {
        connection_pool* pConn = p_msg_header->conn_pool;

        if(timeout_kick)
        {
            forwardly_close_socket(pConn);
        }
        else if((cut_time - pConn->lastPing_time) > (heartPacket_wait_time*3+10))
        {
            Logger::write_to_screen("未收到心跳包，超过最长忍受时限，断开连接");
            forwardly_close_socket(pConn);  //主动断开连接
        }
        memory->free_Memory(p_msg_header);
    }
    else   //如果此连接已经断开了，则释放资源
    {
        memory->free_Memory(p_msg_header);
    }
}
//
// Created by JiangKan on 2019/4/29.
//

#ifndef SIM_SERVER_COMMON_STRUCT_H
#define SIM_SERVER_COMMON_STRUCT_H

//命令码
const short CMD_PING = 0;       //心跳包
const short CMD_REDISTER = 5;    //注册
const short CMD_LOGIN = 6;       //登录

#pragma pack(1)  //1字节对齐，需要要网络传输
struct STRUCT_REGISTER
{
    int code;
    char useranme[56];
    char password[40];
};



struct STRUCT_LOGIN
{
    char username[56];
    char password[40];
};




#pragma pack()   //取消一字节对齐


#endif //SIM_SERVER_COMMON_STRUCT_H

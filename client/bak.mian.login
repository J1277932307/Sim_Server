#include <unistd.h>
#include <iostream>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include "CRC32.h"




using namespace std;


#pragma pack(1)
typedef struct PKG_HEADER
{
    unsigned short pkg_len;
    unsigned short msg_code;
    int CRC32;

}pkg_header;




typedef struct LOGIN
{
    char username[56];
    char password[40];
}pkg_body;
#pragma pack()


int sendData(int sock,int want_to_send_size,char* sendbuf);


int main()
{
    int server_socket = socket(AF_INET,SOCK_STREAM,0);
    struct sockaddr_in server_addr;
    memset(&server_addr,0,sizeof(sockaddr));

    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    server_addr.sin_port = htons(8080);




    unsigned short  header_len = sizeof(PKG_HEADER);
    unsigned short  body_len = sizeof(LOGIN);

    char* p_sendbuf = (char*)new char[header_len+body_len];

    pkg_header* header = (pkg_header*)p_sendbuf;


    header->pkg_len = htons(header_len+body_len);
    header->msg_code = htons(6);

    pkg_body* body = (pkg_body*)(p_sendbuf + header_len);


    strcpy(body->username,"jiang");
    strcpy(body->password,"123456");

    int cal_crc = CRC32::getInstance()->get_CRC((unsigned char*)body,body_len);
    header->CRC32 = htonl(cal_crc);







    connect(server_socket,(struct sockaddr*)&server_addr,sizeof(struct sockaddr));


    sendData(server_socket,(header_len+body_len),p_sendbuf);
    char msg[128];
    recv(server_socket,msg,128,MSG_WAITALL);

    delete [] p_sendbuf;

    cout << "此程序执行完毕" <<endl;



}

int sendData(int sock,int want_to_send_size,char* sendbuf)
{
    int u_send = want_to_send_size;   //未发送的数目
    int uwrote = 0;  //已发送的数目
    int tem_sret;


    while(uwrote < u_send)
    {
        tem_sret = send(sock,sendbuf+uwrote,u_send-uwrote,0);
        cout << "发送了：" << tem_sret <<"个字节" <<endl;
        uwrote += tem_sret;
    }

    return uwrote;

}


#include <unistd.h>
#include <sys/ioctl.h>
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
}pkg_body_login;


typedef struct REGISTER
{
    int identifying_code;
    char username[56];
    char password[40];
}pkg_body_reg;
#pragma pack()


unsigned short  header_len = sizeof(PKG_HEADER);
unsigned short  body_len = sizeof(REGISTER);
int server_socket = socket(AF_INET,SOCK_STREAM,0);


int sendData(int sock,int want_to_send_size,char* sendbuf);
int sendHeartPacket();
long long  recvData(int sock,char* precvBuffer);
int pkg_header_len = sizeof(pkg_header);

int main()
{

    int nb = 1;
    ioctl(server_socket, FIONBIO, &nb);
    struct sockaddr_in server_addr;
    memset(&server_addr,0,sizeof(sockaddr));

    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    server_addr.sin_port = htons(8080);






    char* p_sendbuf = (char*)new char[header_len+body_len];

    pkg_header* header = (pkg_header*)p_sendbuf;


    header->pkg_len = htons(header_len+body_len);
    header->msg_code = htons(5);

    pkg_body_reg* body = (pkg_body_reg*)(p_sendbuf + header_len);


    int id_code = 20;
    body->identifying_code = htonl(id_code);
    strcpy(body->username,"jiang");
    strcpy(body->password,"123456");

    int cal_crc = CRC32::getInstance()->get_CRC((unsigned char*)body,body_len);
    header->CRC32 = htonl(cal_crc);







    connect(server_socket,(struct sockaddr*)&server_addr,sizeof(struct sockaddr));


    cout<<"####################################"<<endl;
    cout<<"         输入s:    发送数据包  "<<endl;
    cout<<"         输入r:    接收数据包  "<<endl;
    cout<<"         输入h:    发送心跳包  "<<endl;
    cout<<"         输入q:    退出整个程序"<<endl;
    cout<<"####################################"<<endl;
    cout <<endl;
    cout<<">>";
    char ifs;
    while(cin >>ifs)
    {

        if(ifs == 's')
        {
            sendData(server_socket,(header_len+body_len),p_sendbuf);

        }
        else if(ifs == 'r')
        {
            char msg[100000] = {0};
            auto count = recv(server_socket,msg,100000,0);
            if(count == -1)
            {
                cout << "没有数据可以接收" <<endl;
            }
            else if(count > 0)
            {
                int sum = 0;
                pkg_header *pkgHeader;
                REGISTER *msg_recv_body;
                char *msg_recv = msg;


                while (sum < count)
                {
                    pkgHeader = (PKG_HEADER *)msg_recv;

                    int code_type = ntohs(pkgHeader->msg_code);
                    switch (code_type)
                    {
                        case 5:
                            cout << "收到了服务器发来的" << (header_len+body_len) << "个字节" << endl;
                            pkgHeader = (PKG_HEADER *) (msg_recv);
                            msg_recv_body = (REGISTER *) (msg_recv + pkg_header_len);
                            cout << "接到了数据：" << msg_recv_body->username << endl << "data code："<< ntohs(pkgHeader->msg_code) << endl;


                            msg_recv += (header_len + body_len);
                            sum += (header_len + body_len);
                            break;

                        case 0:
                            cout << "收到了服务器发来的" << header_len << "个字节" << endl;
                            pkgHeader = (PKG_HEADER *) (msg_recv);
                            cout <<"data code："<< ntohs(pkgHeader->msg_code) << endl;

                            msg_recv += header_len ;
                            sum += header_len;
                            break;

                        case 6:
                            break;
                        default:
                            break;

                    }
                }
                pkgHeader = nullptr;
                msg_recv_body = nullptr;
                msg_recv = nullptr;
            }
            else
            {
                //收到0个字节，说明对方断线了，这里主要用来测试心跳包
            }

        }
        else if(ifs == 'q')
        {
            exit(0);
        }
        else if(ifs == 'h')
        {
            sendHeartPacket();
        } else
        {
            continue;
        }
        cout <<">>";


    }
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
//收数据
long long recvData(int sock,char* precvBuffer)
{
    long long bytes;   //收到的包字节
    char* ptmbuf;  //指向存储包的的位置
    long long  sum_bytes;  //总共收了这么多字节
    long long allowbytes;    //下次还收多少字节

    bytes = recv(sock,precvBuffer,pkg_header_len,0); //先出一个包头的长度

    if(bytes < 0)
    {
        cout << "收包失败，退出！"<<endl;
        exit(-1);
    }
    ptmbuf = precvBuffer;
    allowbytes = pkg_header_len;
    sum_bytes += bytes;


    if(bytes < pkg_header_len)
    {

        contrecvhead:
        allowbytes = allowbytes-bytes;
        ptmbuf = ptmbuf+bytes;
        bytes = recv(sock,ptmbuf,allowbytes,0);
        if(bytes < 0)
        {
            cout << "收包头失败，退出！"<<endl;
            exit(-1);
        }
        if(bytes < allowbytes)
        {
            goto contrecvhead;
        }
        goto recvbody;
    }
    recvbody:
    pkg_header* pkgheader_p;
    pkgheader_p = (pkg_header*)precvBuffer;
    unsigned short iLen = ntohs(pkgheader_p->pkg_len);
    if(iLen == pkg_header_len)
    {
        return iLen;
    }
    allowbytes = iLen = pkg_header_len;
    ptmbuf = precvBuffer+ pkg_header_len;


    contrecv2:
    bytes = recv(sock,ptmbuf,allowbytes,0);
    if(bytes < 0)
    {
        cout << "收包体失败，退出！"<<endl;
        exit(-1);
    }
    sum_bytes += bytes;
    if(bytes < allowbytes)
    {
        allowbytes = allowbytes - bytes;
        ptmbuf = ptmbuf +bytes;
        goto contrecv2;
    }

    return sum_bytes;
}

int sendHeartPacket()
{
    char* p_sendbuf = (char*)new char[header_len];

    pkg_header* header = (pkg_header*)p_sendbuf;

    header->pkg_len = htons(header_len);
    header->msg_code = 0;
    header->CRC32 = 0;


    sendData(server_socket,header_len,p_sendbuf);
}

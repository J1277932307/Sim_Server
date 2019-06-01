//
// Created by JiangKan on 2019/4/22.
//

#ifndef SIM_SERVER_SOCKET_H
#define SIM_SERVER_SOCKET_H
#include <netinet/in.h>
#include <thread>
#include <vector>
#include <list>
#include <atomic>
#include <mutex>
#include <map>
#include <memory>
#include <semaphore.h>
#include "sys/epoll.h"


//######------这里主要定义与包头有关的结构------#####//
//这里使用一字节对齐，因为需要在网络上传输，所以需要保证对端主机与我方主机在字节对齐的一致性
#pragma pack(1)
struct PKG_HEADER
{
    unsigned short pkg_len;    //一个包的总长度，包括包头和包体
    unsigned short msg_code;   //消息类型代码，用于区别不同的命令
    int CRC32;                 //CRC32校验
};
#pragma pack()


//定义接收包的状态标志
enum PKG_RECV_STATUS
{
    PKG_HD_INIT,      //初始状态，准备接收包头
    PKG_HD_RECVING,   //接收包头中，接收的包头不完整，需要继续接收包头
    PKG_BD_INIT,      //包头刚好收完，开始接收包体
    PKG_BD_RECVING    //包体接收不完整，需要继续接收
};


const int PKG_MAX_LENGTH = 30000;     //定义每个包最大的长度
const int HEADER_SIZE = 20;           //因为要先收包头，定义一个固定大小的数组专门用来收包头


//######------这里主要定义与socket和连接池有关的结构------#####//
//前置声明
typedef struct listen_socket_struct listen_socket;
typedef struct connection_pool_struct connection_pool;
typedef class Socket Socket;

typedef void (Socket::*event_handler_ptr)(connection_pool *con);

//监听套接字结构体
struct listen_socket_struct
{
    int fd;        //记录监听套接字的fd
    int port;      //监听套接字的端口号
    connection_pool *connection;   //监听套接字绑定的连接池内存


};


//定义线程的类别
enum THREAD_TYPE{
    SEND,
    RECY,
    MONITOR
};

//连接池结构体
struct connection_pool_struct
{
    connection_pool_struct();
    virtual ~connection_pool_struct();
    void get_connection_to_use();
    void put_connection_to_free();


    int fd;                         //这个fd保存套接字
    listen_socket *listen;          //指向监听套接字结构体

    unsigned long long current_sequence;      //这个东西主要用来保证连接池的有效性
    struct sockaddr socket_addr;


    event_handler_ptr read_handler; //读事件的相关处理方法
    event_handler_ptr write_handler;//写事件的相关处理方法，这里的读与写是相对于服务端来讲的，比如客户的请求来了，那么对于服务端来说这个套接字就是可读的了


    //epoll事件相关
    unsigned int events;

    //收包相关
    int pkg_stat;                    //收包状态，用于表示收包进行的过程，如果一个包头一次没有收完整，那么下次我们还将继续收包头
    char header[HEADER_SIZE];        //用于保存收到的包头
    char*  ptr_recvbuf;              //接收数据缓冲区的头指针
    size_t recv_len;                 //指示需要收到的包的长度，我们将其初始化包头长度，如果不满足这个长度，我们将继续收，直到其满足此长度，我们再进行下一步操作
    //bool is_new_mem;               //指示是否为其分配过内存，回收时判断此值，如果分配过，则需要记得回收
    char*  pkg_memory_pointer;       //new出来的用于收包的内存首地址

    std::mutex logic_mutex;          //定义一个互斥量，用于用户逻辑业务的互斥

    //发包相关
    std::atomic<int> send_count;     //记录发送缓存区是否已满，如果满了，则需要用epoll驱动消息继续发送
    char* sent_memory_pointer;       //指向一个已经向客户端发送过的包的内存首地址，用来释放此内存：消息头 + 包头 + 包体
    char* send_buf;                  //发送数据缓冲区首地址，格式：包头 + 包体
    unsigned int send_size;          //要发送多少数据

    //和回收相关
    time_t recycle_time;             //记录放到资源回收队列时的时间

    //和心跳包有关
    time_t lastPing_time;            //记录上次心跳包到来的时间

    //和网络安全相关
     uint64_t flood_kick_last_time;  //记录上次flood攻击的时间
     int flood_attack_count;         //记录flood攻击在该时间内收到包的次数统计


    connection_pool* next;          //指向下一个连接池内结构，彼此构成一个链表

};


//消息头结构体
//消息头主要用在服务器端，记录一些额外的信息，不在网络进行传输，所以不用一字节对齐
struct MSG_HEADER
{
    connection_pool* conn_pool;        //指向对应的连接池
    unsigned long long cur_sequence;   //收到数据包时记录对应连接的序号，将来能用于比较是否连接已经作废用
};






class Socket
{
private:

    enum{LISTEN_NUM = 511,MAX_EVENTS = 512};                         //定义listen监听总数，epoll监听的事件总数

    struct thread_item                              //线程结构体，主要用来保存一些线程相关的参数，主要有两个线程用到，一个是发数据线程，一个是回收线程
    {
        std::shared_ptr<std::thread> p_thread;      //线程句柄
        Socket *p_this;                             //记录连接池的指针
        bool is_running;                            //标志线程是否正式启动起来
        THREAD_TYPE type;                                    //标志启动线程是发数据线程还是回收线程


        explicit thread_item(Socket *pthis,THREAD_TYPE thread_type); // 'r'代表回收线程，默认值
        ~thread_item();
    };

    int worker_connection;                          //epoll监听socket的最大数目
    int listen_port_number;                         //监听的端口数量
    int epoll_fd;                                   //使用epoll_create创建epoll结构后返回的文件描述符

    //连接池相关
    std::list<connection_pool*> connection_list;    //总连接列表
    std::list<connection_pool*> free_conntion_list; //空闲连接列表
    std::atomic<int> total_conn_num;                //连接池总连接数量
    std::atomic<int> free_conn_num;                 //空闲连接数量
    std::mutex conn_list_mutex;                     //连接池相关互斥量，互斥connection_list和free_conntion_list
    std::mutex recycle_conn_list_mutex;             //回收列表相关互斥量
    std::list<connection_pool*> recycle_conn_list;  //将准备释放的连接放在这里面
    std::atomic<int> total_recycle_conn_num;        //待释放连接数量
    int recycle_wait_time;                          //回收连接的等待时间，即连接过期后，在N秒后我们放回收这个连接

    std::vector<listen_socket *> listen_socket_list;//定义一个用于存储监听套接字的容器
    struct epoll_event events[MAX_EVENTS];          //这里面保存epoll_wait()返回的事件

    //消息队列相关
    std::list<char*> msg_send_Queue;                //发送消息队列
    std::atomic<int> msg_send_count;                //发送消息队列中，消息的总数

    //和多线程互斥相关
    std::mutex send_msg_mutex;                      //发消息队列互斥量
    std::vector<thread_item*>  thread_container;    //线程容器
    sem_t sem_event_send_Queue;                     //处理发消息相关的信号量

    //心跳包时间相关
    int if_kick_time_enable;                        //是否开启踢人时间，即如果对方迟迟不发心跳包，就踢掉他的连接
    std::mutex time_queue_mutex;                    //时间队列相关互斥量
    std::multimap<time_t ,MSG_HEADER*> time_Queue;  //时间队列
    size_t time_Queue_size;                         //时间队列大小
    time_t timer_value;                             //当前时间队列头部时间

    //在线用户相关
    std::atomic<int> onlineUserCount;               //统计用户连接总数，用于限制并发连接数量

    //网络安全相关
    int flood_check_Enable;                         //开启洪泛攻击检测标志位
    unsigned int flood_time_Interval;               //表示收包频率，即N毫秒收一个包
    int flood_kick_Count;                           //累积多少次就可以判断为洪泛攻击


    //接下来是一些私有函数
    //打开并监听套接字
    bool open_and_listening_sockets();

    //关闭监听套接字
    void close_sockets();

    //设置套接字为非阻塞
    bool set_nonblocking(int socket);

    //事件接收函数
    void event_accept(connection_pool* listen_socket);

    //用户读请求操作函数
    void read_request_handler(connection_pool* pConn);

    //可写操作函数
    void write_request_handler(connection_pool* pConn);

    //关闭并回收某个连接对象
    void close_connection(connection_pool* pConn);

    //接收从客户端发过来的数据
    ssize_t recv_data(connection_pool* pConn,char* buff,ssize_t buf_len);

    //包头收完整后的处理，我们称为包处理阶段1：写成函数，方便复用
    void after_recv_pkg_header(connection_pool* pConn,bool& isflood);

    //收到一个完整包后的处理，我们称为包处理阶段2，放到一个函数中，方便调用
    void after_recv_full_pkg(connection_pool* pConn,bool& isflood);

    //清理发送消息队列
    void clear_msg_send_Queue();

    //发送数据给客户端
    ssize_t send_data(connection_pool* pConn,char* buff,ssize_t size);

    //下面是连接池相关函数
    //初始化连接池
    void init_connection_pool();
    
    //清空连接池
    void clear_connection_pool();
    
    //从连接池中获取一个连接对象
    connection_pool* get_connection_from_pool(int socket);
    
    //释放某个连接池对象
    void free_connection(connection_pool* pConn);

    //将要回收的连接对象放入一个回收队列当中
    void put_connection_to_Recy_Queue(connection_pool* pConn);

    //线程相关函数
    //发送数据的线程调用此函数发送数据
    static void* send_data_thread(void* thread_data);

    //连接对象回收线程调用此函数回收连接对象
    static void* recy_connection_thread(thread_item* thread_data);

    //时间队列监视线程使用此函数监视时间队列中对象是否超时
    static void* time_Queue_Monitor_thread(thread_item* thread_data);

    //和时间队列相关的函数
    //添加连接对象到时间队列当中
    void add_to_Timer_Queue(connection_pool* pConn);

    //获取时间队列当中最早的时间
    time_t get_Earliest_time();

    //从m_timeQueuemap移除最早的时间，并把最早这个时间所在的项的值所对应的指针返回
    MSG_HEADER* remove_first_Timer();

    //根据给的当前时间，从m_timeQueuemap找到比这个时间更老（更早）的节点【1个】返回去，这些节点都是时间超过了，要处理的节点
    MSG_HEADER* get_overtime_timer(time_t cur_time);

    //把指定用户的连接从时间队列踢出去
    void delete_frome_Time_Queue(connection_pool* pConn);

    //清空时间队列
    void clear_Time_Queue();

    //flood攻击检测
    bool flood_check(connection_pool* pConn);


protected:
    //网络通讯包相关的数据
    size_t pkg_header_len;                          //记录包头的长度
    size_t msg_header_len;                          //记录信息头的长度

    //心跳包检测时间
    int heartPacket_wait_time;

    //连接限时标志位
    int timeout_kick;                              //标志是否开启连接限时功能，如果一个连接长时间连入服务器不主动断开，则踢掉

    //将待发送消息放入送消息队列
    void put_to_msg_Queue(char* sendbuf);

    //主动关闭一个连接时，进行相关善后工作
    void forwardly_close_socket(connection_pool* pConn);

public:
    //构造函数
    Socket();

    //析构函数
    virtual ~Socket();

    //初始化函数，主要在父进程中执行
    virtual bool initialize();

    //初始化函数，主要在子进程中执行
    virtual bool initialize_sub_process();

    //关闭退出子进程,在子进程中执行
    virtual void shutdown_sub_process();

    //处理客户端请求,将来可能在子类中重写
    virtual void thread_recv_proc_func(char* msgbuf);

    virtual void ping_timeout_checking(MSG_HEADER* p_msg_header,time_t cut_time);

    //epoll功能初始化
    int epoll_init();

    //epoll等待接收和初步处理事件
    int epoll_process(int timer);

    //epoll操作事件
    int epoll_operate_event(int fd,unsigned int event_type,unsigned int flag,int action,connection_pool* p_Conn );




};


#endif //SIM_SERVER_SOCKET_H

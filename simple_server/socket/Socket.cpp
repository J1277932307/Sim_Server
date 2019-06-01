//
// Created by JiangKan on 2019/4/22.
//

#include <unistd.h>
#include <string>
#include <sys/ioctl.h>
#include <chrono>
#include "Socket.h"
#include "../memory/Memory.h"
#include "../configurer/Configurer.h"
#include "../log/Logger.h"


class Socket;
/*--------------------下面connection_pool_struct成员函数--------------------------------------*/

//连接池结构体的构造函数
connection_pool_struct::connection_pool_struct()
{
    current_sequence = 0;    //将序列号初始化为零，此序列号主要用来识别连接对象是否已经过期
}

//连接池析构函数，啥也不用干
connection_pool_struct::~connection_pool_struct() {};

//分配出去一个连接的时候对此连接对象进行一些内容的初始化
void connection_pool_struct::get_connection_to_use()
{
    ++current_sequence;              //序列定义为原子的，所以用++
    pkg_stat = PKG_HD_INIT;          //定义包接收的状态为刚刚要接收包头
    ptr_recvbuf = header;            //将ptr_recvbuf指向存储包头的地址，将来用此指针前向迭代，处理数据
    recv_len = sizeof(PKG_HEADER);   //指定需要接收的数据大小，为一个包头的大小，在接收过程中，这个recv_len是不断变化的，其主要作用是指定下次接收多大的包
    pkg_memory_pointer = nullptr;    //指定new出来的用于保存整个包的的内存的首地址，这里先给nullptr
    send_count = 0;                  //发送缓存区已满标志位，如果发送区已满，则需要用epoll驱动发送数据，如果不满，则可以手动调用send函数发送就可以，主要是解决LT反复触发问题
    sent_memory_pointer = nullptr;   //指向发送完成的包内存首部，用于释放这个存储包的内存
    events = 0;                      //epoll事件先给个0
    lastPing_time = time(nullptr);   //上次心跳包到来的时间
    flood_kick_last_time = 0;        //flood上次攻击包到达的时间
    flood_attack_count = 0;          //在给定时间内收到flood攻击包的次数



}

//回收一个连接对象
void connection_pool_struct::put_connection_to_free()
{
    ++current_sequence;              //再++,拿出去加一次，收回来，再加一次，两个序列不一样，则标志此连接对象失效
    if (pkg_memory_pointer != nullptr)//如果为这个连接分配过接收数据的内存， 则释放
    {
        Memory::getInstance()->free_Memory(pkg_memory_pointer);
        pkg_memory_pointer = nullptr;
    }
    if (sent_memory_pointer != nullptr)//如果为这个连接分配过发送数据的内存，则释放
    {
        Memory::getInstance()->free_Memory(sent_memory_pointer);
        sent_memory_pointer = nullptr;
    }
    send_count = 0;                   //发送缓存区满 标志位置还原
}

/*--------------------下面是Socket下的thread_item成员函数--------------------------------------*/

Socket::thread_item::thread_item(Socket *pthis,THREAD_TYPE thread_type) : p_this(pthis), is_running(false),type(thread_type)
{
    if(type == SEND)           //如果是发数据线程
    {
        p_thread.reset(new std::thread(&Socket::send_data_thread,this));
    }
    else if(type == RECY)       //回收线程
    {
        p_thread.reset(new std::thread(&Socket::recy_connection_thread,this));
    }
    else if(type == MONITOR)    //时间队列监视线程
    {
        p_thread.reset(new std::thread(&Socket::time_Queue_Monitor_thread,this));
    }

}

Socket::thread_item::~thread_item() {};   //因为使用了智能指针，这里不考虑销毁问题

/*--------------------下面是Socket成员函数----------------------------------------------------*/

//Socket构造函数
Socket::Socket()
{
    worker_connection = 1;              //epoll最大连接数，先初始化为1，后面从配置文件中读出来再赋过来
    listen_port_number = 1;             //监听端口数量，可能是1个，也可能是N个，先初始化为1，后面从配置文件中读出来再赋过来
    recycle_wait_time = 15;             //等待这么多秒后，才开始真正的回收连接
    epoll_fd = -1;                      //epoll_create()返回的句柄
    pkg_header_len = sizeof(PKG_HEADER);//包头大小
    msg_header_len = sizeof(MSG_HEADER);//消息头大小

    msg_send_count = 0;                 //发送消息队列中的消息数量
    total_recycle_conn_num = 0;         //延迟回收连接队列的大小
    onlineUserCount = 0;                //有多少用户连接进来，刚开始为0
}

//Socket析构函数
Socket::~Socket()
{
    //释放监听端口相关内存
    for (auto begin = listen_socket_list.begin(); begin != listen_socket_list.end(); ++begin)
    {
        delete (*begin);
    }
    listen_socket_list.clear();
    return;
}


//主进程中需要对Socket进行的初始化，即在fork之前需要完成的工作
bool Socket::initialize()
{
    Configurer *conf = Configurer::getInstance();
    worker_connection = std::stoi(conf->get_config_by_name("worker_connection"));       //读取配置文件中规定的epoll连接数量
    listen_port_number = std::stoi(conf->get_config_by_name("listen_port_number"));     //读取配置文件中规定的监听套接字数量
    recycle_wait_time = std::stoi(conf->get_config_by_name("recycle_wait_time"));       //读取配置文件中规定的回收连接对象等待时间


    if_kick_time_enable = std::stoi(conf->get_config_by_name("Heartbeat_Packet_Enable"));//读取配置文件中是否开启了心跳包功能，1开启
    if(if_kick_time_enable) //如果开启心跳包检测功能，则我们将读取关于此功能的余下配置项
    {
        heartPacket_wait_time = std::stoi(conf->get_config_by_name("MaxWaitTime"));     //读取配置文件中规定的心跳包发送时间
        heartPacket_wait_time = heartPacket_wait_time > 5 ? heartPacket_wait_time : 5;

        //开启连接超时功能，如果用户连入主机时间过长，则服务器主动断开连接
        timeout_kick = std::stoi(conf->get_config_by_name("Timeout_Kick"));
    }

    flood_check_Enable = std::stoi(conf->get_config_by_name("Flood_Attack_Kick_Enable"));//读取配置文件中是否开启了洪泛攻击检测功能，1开启
    if(flood_check_Enable)  //如果开启洪泛攻击检测，则我们将读取关于此功能的余下配置项
    {
        flood_time_Interval = (unsigned int)std::stoi(conf->get_config_by_name("Flood_Time_Interval"));//读取配置文件中规定的收包频率
        flood_kick_Count = std::stoi(conf->get_config_by_name("Flood_Kick_Counter"));    //读取配置文件中规定的统计次数，超过这个次数则认定为flood攻击
    }



    if (open_and_listening_sockets() == false)   //开始监听套接字
        return false;
    return true;
}


//子进程中需要对部分Socket成员完成初始化
bool Socket::initialize_sub_process()
{
    /*
     * 初始化发消息相关信号量，信号量用于进程/线程之间的同步
     * 第二个参数=0，表示信号量在线程之间共享，如果非0，表示在进程之间共享
     * 第三个参数=0，表示信号量的初始值，为0时，调用sem_wait()就会卡在那里卡着
     */
    if (sem_init(&sem_event_send_Queue, 0, 0) == -1)
    {
        Logger::write_to_screen("Socekt::initiallize_sub_process()中sem_init(&sem_event_send_Queue,0,0)失败.");
        return false;
    }

    //创建专门用于发数据的线程
    //thread_item *p_sendQueue;
    thread_container.push_back(new thread_item(this,SEND));

    //创建专门用于回收连接的线程
    //thread_item *p_recyConn;
    thread_container.push_back(new thread_item(this,RECY));

    //创建专门用于检测超时连接的线程
    if(if_kick_time_enable)
    {
        thread_container.push_back(new thread_item(this,MONITOR));
    }



    return true;

}

//关闭退出子进程的函数，在子进程中执行
void Socket::shutdown_sub_process()
{
    if (sem_post(&sem_event_send_Queue) == -1)   //激活信号量，目标是为了让发送数据线程走下来
    {
        Logger::write_to_screen("Socket::shutdown_sub_process()中调用sem_post(&m_semEventSendQueue)失败");
    }

    for (auto iter = thread_container.begin(); iter != thread_container.end(); ++iter)
    {
        //等待线程终止，才能继续关闭进程
        (*iter)->p_thread->join();
    }

    //接下来入释放new出来的thread_item结构对象
    for (auto iter = thread_container.begin(); iter != thread_container.end(); ++iter)
    {
        if (*iter)
            delete (*iter);
    }
    thread_container.clear();

    //清空发送消息队列、连接池、时间队列
    clear_msg_send_Queue();
    clear_connection_pool();
    clear_Time_Queue();

    //销毁信号量
    sem_destroy(&sem_event_send_Queue);
}

//清空消息发送队列
void Socket::clear_msg_send_Queue()
{
    char *tmp_mem_pointer;
    Memory *memory = Memory::getInstance();
    while (!msg_send_Queue.empty())
    {
        tmp_mem_pointer = msg_send_Queue.front();
        msg_send_Queue.pop_front();
        memory->free_Memory(tmp_mem_pointer);
    }
}

//打开并监听套接字
bool Socket::open_and_listening_sockets()
{
    int server_socket;                           //服务器端套接字
    struct sockaddr_in server_addr;              //服务器端地址
    int port;                                    //服务器监听端口
    Configurer* configurer = Configurer::getInstance();


    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;            //IPv4
    server_addr.sin_addr.s_addr = htonl(INADDR_ANY);  //监听本地所有IP地址

    //根据配置文件中指定的监听端口数量，生成套接字
    for (int i = 0; i < listen_port_number; ++i)
    {
        server_socket = socket(AF_INET, SOCK_STREAM, 0);
        if (server_socket == -1)    //创建套接字失败，打印到屏幕
        {
            Logger::write_to_screen("Socket::open_and_listening_sockets()中调用socket()函数生成套接字失败");
            return false;
        }


        //设置套接字快速重用
        int reuseaddr = 1;
        if (setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR, &reuseaddr, sizeof(reuseaddr)) == -1)
        {
            Logger::write_to_screen("Socket::open_and_listening_sockets()中调用setsockopt()设置套接字快速重用失败！");
            close(server_socket);
            return false;
        }

        //设置该socket为非阻塞

        /*
         * 为什么我们要把监听套接字设置为非阻塞？
         * 充分利用时间片，这个解释也不太完美
         *
        */
        if (!set_nonblocking(server_socket))
        {
            Logger::write_to_screen("Socket::open_and_listening_sockets()中调用set_nonblocking()设置socket为非阻塞失败");
            close(server_socket);
            return false;
        }

        //组合配置文件中端口项key值，用于提取配置文件中的端口值
        string str_port = "port";
        str_port.append(std::to_string(i));
        port = std::stoi(configurer->get_config_by_name(str_port));

        //设置监听端口号
        server_addr.sin_port = htons((in_port_t)port);

        //绑定套接字与地址
        if (bind(server_socket, (struct sockaddr*) &server_addr, sizeof(server_addr)) == -1)
        {
            Logger::write_to_screen("Socket::open_and_listening_sockets()中调用bind()绑定套接字地址失败");
            close(server_socket);
            return false;
        }

        //开始监听
        if (listen(server_socket, LISTEN_NUM) == -1)
        {
            Logger::write_to_screen("Socket::open_and_listening_sockets()中调用listen()监听套接字失败");
            close(server_socket);
            return false;
        }


        listen_socket_struct *p_listen_socket_item = new listen_socket_struct;
        memset(p_listen_socket_item, 0, sizeof(listen_socket_struct));
        p_listen_socket_item->port = port;
        p_listen_socket_item->fd = server_socket;


        //保存到日志中
        char str_famt[128];
        Logger *log = Logger::getInstance();
        sprintf(str_famt, "监听%d端口成功！", port);
        log->write_to_log(NOTICE, 0, string(str_famt));

        //将监听对象保存到列表中
        listen_socket_list.push_back(p_listen_socket_item);
    }
    //如果监听列表为空，说明有问题
    if (listen_socket_list.empty())
        return false;
    return true;


}

bool Socket::set_nonblocking(int socket)
{
    int nb = 1;
    if (ioctl(socket, FIONBIO, &nb) == -1)
    {
        return false;
    }
    return true;
}

//关闭监听套接字
void Socket::close_sockets()
{
    for (int i = 0; i < listen_port_number; ++i)
    {
        close(listen_socket_list[i]->fd);
        //保存到日志中
        char str_famt[128];
        Logger *log = Logger::getInstance();
        sprintf(str_famt, "关闭%d端口成功！", listen_socket_list[i]->port);
        log->write_to_log(NOTICE, 0, string(str_famt));

    }
}

//将待发送消息放到发消息队列中
void Socket::put_to_msg_Queue(char *sendbuf)
{
    std::lock_guard<std::mutex> lock(send_msg_mutex);
    msg_send_Queue.push_back(sendbuf);
    ++msg_send_count;        //将消息队列中的消息数+1，这里是原子操作

    //将信号量+1，使后面处理消息队列中的线程走下去
    if (sem_post(&sem_event_send_Queue) == -1)
    {
        Logger::write_to_screen("Socket::put_to_msg_Queue()中调用sem_post()出错！");
    }
}

//epoll初始化
int Socket::epoll_init()
{
    //很多内核版本不处理epoll_create的参数，只要该参数>0即可
    //创建一个epoll对象，创建了一个红黑树，还创建了一个双向链表
    epoll_fd = epoll_create(worker_connection);
    if (epoll_fd == -1)
    {
        Logger::write_to_screen("Socket: Socket::epoll_init()调用epoll_create()失败！");
        exit(2);     //出现致使问题，强行退出，资源由系统释放
    }

    //初始化连接池
    init_connection_pool();

    //将监听套接字与一个连接对象绑定
    for (auto iter = listen_socket_list.begin(); iter != listen_socket_list.end(); ++iter)
    {
        connection_pool *p_Conn = get_connection_from_pool((*iter)->fd);
        if (p_Conn == nullptr)
        {
            //获取到的连接对象为空，非常致命，终止进程，由系统释放资源
            Logger::write_to_screen("从连接池获取连接对象失败，终止进程！");
            exit(2);

        }
        p_Conn->listen = (*iter);     //连接对象和监听对象关联
        (*iter)->connection = p_Conn; //监听对象和连接对象关联

        //监听socket的读事件处理函数，注意，是监听socket，而不是用户三次握手连进来的socket
        //我们使用这个函数调用accept()接受用户三次握手。用户真正的数据请求需要用另外的函数处理
        p_Conn->read_handler = &Socket::event_accept;

        //往监听套接字上面添加事件
        if (epoll_operate_event((*iter)->fd, EPOLL_CTL_ADD, EPOLLIN | EPOLLHUP, 0, p_Conn) ==
            -1)     //EPOLLIN：表示可读  EPOLLHUP：用户断开
        {
            //有问题，直接退出了
            exit(2);
        }
    }
    return 1;
}

//初始化连接池
void Socket::init_connection_pool()
{
    connection_pool *p_Conn;
    Memory *memory = Memory::getInstance();
    int pool_size = sizeof(connection_pool);
    for (int i = 0; i < worker_connection; ++i)
    {
        p_Conn = (connection_pool *) memory->allocMemory(pool_size, true);

        //定位new，上面分配的内存没有调用构造函数，这里使用调用构造函数
        p_Conn = new(p_Conn) connection_pool();

        //进行部分初始化
        p_Conn->get_connection_to_use();

        //将连接对象放入容器中保存
        connection_list.push_back(p_Conn);

        //空闲列表中也保存一份连接对象，因为是初始化过程，所有连接对象都是空闲的
        free_conntion_list.push_back(p_Conn);
    }

    //空闲列表中的数量 = 总连接对象数量 = 保存连接对象容器中的数量
    free_conn_num = total_conn_num = connection_list.size();
}

connection_pool *Socket::get_connection_from_pool(int socket)
{
    //考虑有可能会有其他线程访问线程池，先临界
    std::lock_guard<std::mutex> lock(conn_list_mutex);

    //如果空闲连接队列非空，我们就从中取出连接对象
    if (!free_conntion_list.empty())
    {
        connection_pool *p_Conn = free_conntion_list.front();
        free_conntion_list.pop_front();
        p_Conn->get_connection_to_use();
        --free_conn_num;
        p_Conn->fd = socket;
        return p_Conn;
    }
    //走到这里，表示没有空闲连接了，那就重新创建一个连接
    Memory *memory = Memory::getInstance();
    auto *p_Conn = (connection_pool *) memory->allocMemory(sizeof(connection_pool), true);

    //定位new，手动调用构造函数
    p_Conn = new(p_Conn) connection_pool();
    p_Conn->get_connection_to_use();

    //把新创建的连接对象放入连接对象容器中
    connection_list.push_back(p_Conn);
    ++total_conn_num;
    p_Conn->fd = socket;

    //这里不再把新创建的连接对象放入空闲连接池中，而是直接返回
    return p_Conn;

}

//epoll事件操作
int Socket::epoll_operate_event(int fd, unsigned int event_type, unsigned int flag, int action, connection_pool *p_Conn)
{
    /*
     *fd:表示一个socket
     * event_type:事件类型，一般是EPOLL_CTL_ADD，EPOLL_CTL_MOD，EPOLL_CTL_DEL，操作epoll红黑树的节点
     * flag:标志，具体含义取决于event_type
     * action:补充动作
     * p_Conn:连接对象
     */

    //epoll事件结构体，用于保存epoll事件
    struct epoll_event ev;
    memset(&ev, 0, sizeof(epoll_event));

    if (event_type == EPOLL_CTL_ADD)  //如果是往红黑树中添加节点
    {
        ev.events = flag;        //如果是添加节点，则不用管原来的标志是什么
        p_Conn->events = flag;   //连接本身也记录一下
    } else if (event_type == EPOLL_CTL_MOD)  //如果是修改节点的事件信息
    {
        ev.events = p_Conn->events;
        if (action == 0)
        {
            ev.events |= flag;  //添加某个标记
        } else if (action == 1)
        {
            ev.events &= ~flag;  //删除某个标记
        } else
        {
            ev.events = flag;    //完全覆盖某个标记
        }
    } else
    {
        //走到这里应该是删除红黑树节点，目前没这个需求【socket关闭这项会自动从红黑树移除】，所以将来再扩展
        return 1;
    }

    ev.data.ptr = (void *) p_Conn;
    if (epoll_ctl(epoll_fd, event_type, fd, &ev) == -1)
    {
        Logger::write_to_screen("Socket::epoll_operate_event()调用epoll_ctl()失败");
        return -1;
    }

    return 1;
}

//epoll事件处理函数，一旦用户请求过来，我们会在这个函数里预处理
int Socket::epoll_process(int timer)
{
    int event_count = epoll_wait(epoll_fd, events, MAX_EVENTS, timer);
    Logger *logger = Logger::getInstance();
    if (event_count == -1)
    {
        /* 有错误发生，发送某个信号给本进程就可以导致这个条件成立，而且错误码根据观察是4；
         * #define EINTR  4，EINTR错误的产生：当阻塞于某个慢系统调用的一个进程捕获某个信号且相应信号处理函数返回时，该系统调用可能返回一个EINTR错误。
         * 例如：在socket服务器端，设置了信号捕获机制，有子进程，当在父进程阻塞于慢系统调用时由父进程捕获到了一个有效信号时，内核会致使accept返回一个EINTR错误(被中断的系统调用)。
        */

        if (errno == EINTR)
        {
            //信号导致的话，不认为是错误，记录日志直接返回即可
            logger->write_to_log(NOTICE, errno, "Socket::epoll_process()调用epoll_wait()失败");
            return 1;
        } else
        {
            //走到这里，有问题，记录日志
            logger->write_to_log(WARN, errno, "Socket::epoll_process()调用epoll_wait()失败");
            return 0;
        }
    }
    if (event_count == 0)  //超时，但事件没来，是有问题的，因为我们timer会给-1，是一直等待的，不会出现超时
    {
        if (timer != -1)
        {
            //如果并非一直阻塞，则正常返回
            return 1;
        }
        //走下来就是无限等待，还能超时返回，绝对是有问题的，记录日志
        logger->write_to_log(ALERT, 0, "Socket::epoll_process()中epoll_wait()超时，却没有任务事件返回");
        return 0;  //非正常返回
    }

    //正常走下来，就是有事件收到了
    connection_pool *p_Conn;
    unsigned int rev_events;

    for (int i = 0; i < event_count; ++i)
    {
        p_Conn = (connection_pool *) (events[i].data.ptr);
        rev_events = events[i].events;

        if (rev_events & EPOLLIN)  //读事件
        {
            //如果是读事件，就调用读事件处理函数
            (this->*(p_Conn->read_handler))(p_Conn);
        }

        if (rev_events & EPOLLOUT)  //写事件或对面关闭连接也会触发这个
        {
            if (rev_events & (EPOLLERR | EPOLLHUP | EPOLLRDHUP))
            {
                //EPOLLERR：对应的连接发生错误
                //EPOLLHUP：对应的连接被挂起
                //EPOLLRDHUP：表示TCP连接的远端关闭或者半关闭连接

                //我们只有在epoll投递了写事件，才能走到这里，也就意味着send_count一定是被++过了，用户断开，我们这里再减回去
                --p_Conn->send_count;
            } else
            {
                //走到这里来，才是触发真正的写事件
                // 如果有数据没有发送完毕，由系统驱动来发送，即通过把写事件添加到epoll中，通过epoll驱动发送后续数据
                (this->*(p_Conn->write_handler))(p_Conn);
            }
        }
    }
    return 1;
}

//发送消息队列，由专用于发送数据的线程调用此函数
void *Socket::send_data_thread(void *thread_data)
{
    thread_item *p_thread = static_cast<thread_item *>(thread_data);
    Socket *p_socket_obj = p_thread->p_this;   //获取与线程对象绑定的Socket对象

    int err;
    char *p_msg_buf;
    std::list<char *>::iterator begin, pos_temp, end;
    MSG_HEADER *p_msg_header;  //指向信息头的指针
    PKG_HEADER *p_pkg_header;  //指向包头的指针
    connection_pool *p_Conn;
    unsigned short itmp;
    ssize_t sent_size;

    Memory *memory = Memory::getInstance();

    while (g_stop_pro == 0)  //程序不退出
    {
        if (sem_wait(&p_socket_obj->sem_event_send_Queue) == -1)
        {
            if (errno == EINTR)     //这个不算是错误，走下去就好
                Logger::write_to_screen("Socket::send_data_thread()调用sem_wait错误");
        }


        if (g_stop_pro != 0)  //要求整个程序退出
            break;

        //走到下面需要处理数据发送
        if (p_socket_obj->msg_send_count > 0)
        {
            std::unique_lock<std::mutex> lock(p_socket_obj->send_msg_mutex);
            begin = p_socket_obj->msg_send_Queue.begin();
            end = p_socket_obj->msg_send_Queue.end();

            while (begin != end)
            {
                p_msg_buf = (*begin);
                p_msg_header = (MSG_HEADER *) p_msg_buf;
                p_pkg_header = (PKG_HEADER *) (p_msg_buf + p_socket_obj->msg_header_len);
                p_Conn = p_msg_header->conn_pool;

                //判断包是否过期，两序列不相等，则是过期包
                if (p_Conn->current_sequence != p_msg_header->cur_sequence)
                {
                    pos_temp = begin;
                    ++begin;
                    p_socket_obj->msg_send_Queue.erase(pos_temp); //从发送队列中丢弃过期包
                    --p_socket_obj->msg_send_count;               //发送队列消息数减1
                    memory->free_Memory(p_msg_buf);               //回收这个消息的存储内存
                    continue;
                }

                //send_count大于0，说明发送缓存区已满，我们需要epoll驱动，等待发送缓存区空闲来发送
                if (p_Conn->send_count > 0)
                {
                    //靠epoll驱动来发送，所以这里不再发送
                    ++begin;
                    continue;
                }

                //走到这里，才是我们手动发送消息
                p_Conn->sent_memory_pointer = p_msg_buf;    //发送后释放用的
                pos_temp = begin;
                ++begin;
                p_socket_obj->msg_send_Queue.erase(pos_temp);
                --p_socket_obj->msg_send_count;              //发送队列中消息数减1
                p_Conn->send_buf = (char *) p_pkg_header;      //要发送的数据的缓冲区指针，因为发送数据不一定全部都能发送出去，我们要记录数据发送到了哪里，需要知道下次数据从哪里开始发送
                p_Conn->send_size = ntohs(p_pkg_header->pkg_len);    //要发送多少数据，因为发送数据不一定全部都能发送出去，我们需要知道剩余有多少数据还没发送

                //测试使用,输出到屏幕上
                char info_strfmt[128];
                //sprintf(info_strfmt, "即将发送数据%d", p_Conn->send_size);
                Logger::write_to_screen(string(info_strfmt));

                sent_size = p_socket_obj->send_data(p_Conn, p_Conn->send_buf,p_Conn->send_size);  //手动调用函数发送数据，并返回发送的的数据字节长度


                if (sent_size > 0)
                {
                    if (sent_size == p_Conn->send_size)  //发送的数据长度等于既定的发送长度，即一次性把数据发放完毕
                    {
                        //释放此数据占用的全部空间
                        memory->free_Memory(p_Conn->sent_memory_pointer);
                        p_Conn->sent_memory_pointer = nullptr;
                        p_Conn->send_count = 0;       //epoll驱动标志位，如果我们没有一次性把数据发送完毕，有可能是发送缓存区满，则剩余数据需要使用epoll驱动发送，此标志位自增1，此处，其原本就应该是0

                        //测试用
                       // Logger::write_to_screen("Socket::send_data_thread()数据发送完毕");

                    } else   //如果没有全部发送完毕，则剩余数据使用epoll驱动发送，把可写事件投递到epoll当中
                    {
                        p_Conn->send_buf = p_Conn->send_buf + sent_size;  //上次发送到哪里了
                        p_Conn->send_size = p_Conn->send_size - sent_size;  //剩余多少没有发送
                        ++p_Conn->send_count;    //标志使用epoll驱动发送剩余数据

                        if(p_socket_obj->epoll_operate_event(p_Conn->fd,EPOLL_CTL_MOD,EPOLLOUT,0,p_Conn) == -1)   //添加写事件到epoll中
                        {
                            //添加写事件出错
                            Logger::write_to_screen("Socket::send_data_thread()中调用epoll_operate_event()添加写事件出错");
                        }

                        //测试
                        char info_strmat[256];
                        sprintf(info_strmat,"send_data_thread()数据没有发送完毕，整个要发送%d个字节,实际发送%d个字节",p_Conn->send_size,(int)sent_size);
                        Logger::write_to_screen(info_strmat);
                    }
                    continue;
                }else if(sent_size == 0)  //能走下来就是有问题的
                {
                    //发送0个字节，首先因为我发送的内容不是0个字节的；
                    //然后如果发送 缓冲区满则返回的应该是-1，而错误码应该是EAGAIN，所以综合认为，这种情况就把这个发送的包丢弃了【按对端关闭了socket处理】
                    //然后这个包干掉，不发送了
                    //释放资源
                    memory->free_Memory(p_Conn->sent_memory_pointer);
                    p_Conn->sent_memory_pointer = nullptr;
                    p_Conn->send_count = 0;
                    continue;
                } else if(sent_size == -1)  //走到这里，还是有问题
                {
                    //发送缓存区已经满了，一个字节也没有发送出去
                    ++p_Conn->send_count;  //剩余数据使用epoll驱动发送
                    if(p_socket_obj->epoll_operate_event(p_Conn->fd,EPOLL_CTL_MOD,EPOLLOUT,0,p_Conn) == -1)
                    {
                        //添加写事件失败，往屏幕打印一下看看
                        Logger::write_to_screen("send_data_thread()调用epoll_operate_event(）添加写事件失败");
                    }
                    continue;
                } else
                {
                    //走到这里，一般认为对端断开了，回收资源
                    memory->free_Memory(p_Conn->sent_memory_pointer);
                    p_Conn->sent_memory_pointer = nullptr;
                    p_Conn->send_count = 0;
                    continue;
                }


            }
            lock.unlock();

        }

    }
    return (void*)0;


}

void Socket::event_accept(connection_pool *listen_socket)   //传进来的是监听套接字
{

    struct sockaddr client_addr;  //保存用户主机地址
    socklen_t  cli_addr_len = sizeof(client_addr);  //记录地址结构体长度
    int err; //保存错误码
    log_level level;  //记录日志级别
    int client_socket;  //连接套接字
    static int use_accept4 = 1;  //能够使用accept4()函数标志位，如果不能使用，则需要调用accept()并设置连接套接字非阻塞
    connection_pool* new_conn;  //一个新的连接

    Logger* log  = Logger::getInstance();

    do
    {
        if(use_accept4)  //如果可以使用accept4()
        {
            client_socket = accept4(listen_socket->fd,&client_addr,&cli_addr_len,SOCK_NONBLOCK);
        } else   //如果不能使用accept4()
        {
            client_socket = accept(listen_socket->fd,&client_addr,&cli_addr_len);
        }
        if(client_socket == -1)  //获取连接套接字出错
        {
            err = errno;   //先拿到errno，防止errno因为其他原因瞬间变动

            //对accept、send和recv而言，事件未发生时errno通常被设置成EAGAIN（意为“再来一次”）或者EWOULDBLOCK（意为“期待阻塞”）
            if(err == EAGAIN)   //accept()没准备好，这个EAGAIN错误EWOULDBLOCK是一样的
            {
                return;
            }
            level = ALERT;
            if(err == ECONNABORTED)
            {
                //ECONNRESET错误则发生在对方意外关闭套接字后【您的主机中的软件放弃了一个已建立的连接--由于超时或者其它失败而中止接连(用户插拔网线就可能有这个错误出现)
                //该错误被描述为“software caused connection abort”，即“软件引起的连接中止”。原因在于当服务和客户进程在完成用于 TCP 连接的“三次握手”后，
                //客户 TCP 却发送了一个 RST （复位）分节，在服务进程看来，就在该连接已由 TCP 排队，等着服务进程调用 accept 的时候 RST 却到达了。
                //POSIX 规定此时的 errno 值必须 ECONNABORTED。源自 Berkeley 的实现完全在内核中处理中止的连接，服务进程将永远不知道该中止的发生。
                level = ERR;
            }else if(err == EMFILE || err == ENFILE)
            {
                //EMFILE:进程的fd已用尽
                //ENFILE这个errno的存在，表明一定存在system-wide的resource limits，而不仅仅有process-specific的resource limits。
                level = CRIT;
            }
            //写入日志
           log->write_to_log(level,err,"Socket::event_accept()中调用accept4()失败");

            if(use_accept4 && err ==ENOSYS)  //accept4()函数没实现
            {
                use_accept4 = 0;  //标志不使用accept4();
                continue;
            }
            if(err == ECONNABORTED)  //对方关闭套接字
            {
                //忽略，啥也不用干
            }

            if(err == EMFILE || err == ENFILE)
            {
                //上面处理过了，先不动
            }

            return;
        }

        //走下来就表示accept()或accept4()成功了,我们将新连接的连接套接字绑定一块连接池对象

        if(onlineUserCount >= worker_connection)  //连接数已达到当前并发连接
        {
            char str_famt[128];
            sprintf(str_famt,"超出系统允许的最大连入用户数(最大允许连入数%d)，关闭连入请求(%d)。",worker_connection,client_socket);
            Logger::write_to_screen(string(str_famt));

            close(client_socket);
            return;
        }
        new_conn = get_connection_from_pool(client_socket);
        if(new_conn == nullptr)  //连接池不够用，分配不出来新的对象，则关闭此socket并直接返回
        {
            if(close(client_socket) == -1)
            {
                log->write_to_log(ALERT,errno,"Socket::event_accept()中调用close()关闭连接套接字失败");
            }
            return;
        }

        //走下来即成功获取连接池对象
        //拷贝客户端地址到连接对象
        memcpy(&new_conn->socket_addr,&client_addr,sizeof(cli_addr_len));

        if(!use_accept4)
        {
            if(!set_nonblocking(client_socket))  //设置非阻塞失败，关闭连接对象
            {
                close_connection(new_conn);
                return;
            }
        }
        new_conn->listen = listen_socket->listen;

        //绑定连接对象可读 可写操作函数
        new_conn->read_handler = &Socket::read_request_handler;
        new_conn->write_handler = &Socket::write_request_handler;

        //将可读事件投递到epoll当中进行监听，因为客户端有义务先发起请求
        if(epoll_operate_event(client_socket,EPOLL_CTL_ADD, EPOLLIN | EPOLLRDHUP,0,new_conn) == -1)
        {
            //添加监听失败，则直接关闭此连接
            close_connection(new_conn);
            return;
        }

        if(if_kick_time_enable)
        {
            add_to_Timer_Queue(new_conn);   //如果开启心跳包检测，则把用户的新连接放入检测队列当中
        }
        ++onlineUserCount;                  //每一个新连接进来，我们就+1;
        break;
    }while(true);

}

//关闭并释放某个连接对象
void Socket::close_connection(connection_pool *pConn)
{
    free_connection(pConn);
    if(close(pConn->fd) == -1)
    {
        Logger* logger = Logger::getInstance();
        char info_fmt[128];
        sprintf(info_fmt,"Socket::close_connection()调用close(%d)失败",pConn->fd);
        logger->write_to_log(ALERT,errno,info_fmt);
    }

}

//释放连接对象
void Socket::free_connection(connection_pool *pConn)
{
    std::lock_guard<std::mutex> lock(conn_list_mutex);
    pConn->put_connection_to_free();
    free_conntion_list.push_back(pConn);
    ++free_conn_num;
}

//消息处理线程主函数，专门处理各种接收到的TCP消息
void Socket::thread_recv_proc_func(char *msgbuf)
{
    //这个方法我们将在子类中实现，这里不作过多的操作
}

//可读操作函数,即用户真正的数据传入进来，我们将在这个函数里进行初步处理
void Socket::read_request_handler(connection_pool *pConn)
{
    //接收数据
    bool isflood = false;
    ssize_t reco = recv_data(pConn,pConn->ptr_recvbuf,pConn->recv_len);
    if(reco <= 0)
    {
        //recv_data()函数中已经处理了，这里直接返回
        return;
    }

    //能走下来，说明成功接收到了一些字节，然后进行收包处理
    if(pConn->pkg_stat == PKG_HD_INIT)
    {
        if(reco == pkg_header_len)  //如果收到的数据长度正好等于包头长度，则执行收包头之后的操作
        {
            //收完完整的包头后的操作

            after_recv_pkg_header(pConn,isflood);
        } else   //如果收到的包头不完整，则，再循环收包头，直到收完包头为止
        {
            pConn->pkg_stat = PKG_HD_RECVING;
            pConn->ptr_recvbuf = pConn->ptr_recvbuf+reco;  //指针身后移动reco个字节，指向最后一个数据存储位置之后，方便下直接放入数据
            pConn->recv_len = pConn->recv_len - reco;  //重新指定下次期待收的数据长度，其初始值我们在构造函数中已经指定了，为一个包头的大小
        }
    } else if(pConn->pkg_stat == PKG_HD_RECVING)  //如果还是收包头的状态，那就继续收包头
    {
        if(pConn->recv_len == reco) //要求收到的宽度和实际收到的宽度相等，这里可以理解为一个完整的包头已经收完了
        {
            //执行收完包头后的下一步操作
            after_recv_pkg_header(pConn,isflood);
        } else
        {
            //包头还是没收完，再收
            pConn->ptr_recvbuf = pConn->ptr_recvbuf+ reco;
            pConn->recv_len = pConn->recv_len - reco;  //重新指定下次期待收的数据长度

        }
    } else if(pConn->pkg_stat == PKG_BD_INIT)   //开始收包体
    {
        if(reco == pConn->recv_len)
        {
            //包体刚好收完，执行下一步操作
            if(flood_check_Enable)
            {
                isflood = flood_check(pConn);
            }
            after_recv_full_pkg(pConn,isflood);
        } else
        {
            //包体没收完，设置下次收的变量，下次触发可读事件继续收
            pConn->pkg_stat = PKG_BD_RECVING;
            pConn->ptr_recvbuf = pConn->ptr_recvbuf+reco;
            pConn->recv_len = pConn->recv_len-reco;
        }
    }
    else if(pConn->pkg_stat == PKG_BD_RECVING)
    {
        //如果是收包体的状态，我们继续收包体
        //包体收完整了，执行下一步操作
        if(pConn->recv_len == reco)
        {
            after_recv_full_pkg(pConn,isflood);
        } else
        {
            //包头还没收完整
            pConn->ptr_recvbuf = pConn->ptr_recvbuf + reco;
            pConn->recv_len = pConn->recv_len - reco;
        }
    }
    if(isflood)  //如果判定此连接为flood攻击，则断开
    {
        Logger::write_to_screen("此连接有洪泛攻击倾向，已将其关闭");
        forwardly_close_socket(pConn);
    }

}

//可写事件处理函数
void Socket::write_request_handler(connection_pool *pConn)
{
    Memory* memory = Memory::getInstance();
    ssize_t sendsize = send_data(pConn,pConn->send_buf,pConn->send_size);

    if(sendsize > 0 && sendsize != pConn->send_size)
    {
        //发送了数据，但数据只发送了一部分，发送不完整,这里记录一下
        pConn->send_buf = pConn->send_buf+sendsize;
        pConn->send_size = pConn->send_size - sendsize;
        return;
    }else if(sendsize == -1)
    {
        //发送有问题，打印参考一下
        Logger::write_to_screen("Socket::write_request_handler()调用send_data()失败");
        return;
    }
    if(sendsize > 0 && sendsize == pConn->send_size)
    {
        //成功发送，则把写事件通知从epoll去除
        if(epoll_operate_event(pConn->fd,EPOLL_CTL_MOD,EPOLLOUT,1,pConn) == -1)
        {
            //移除通知写事件出错，处理比较麻烦，先打印看一下
            Logger::write_to_screen("Socket::write_request_handler()中调用epoll_operate_event()移除写事件通知出错！");
        }
        Logger::write_to_screen("Socket::write_request_handler()中的数据发送完毕");
    }

    //走下来，要么数据发送完毕了，要么对端断开了，那么执行收尾工作
    //数据发送完毕，或者把需要发送的数据除掉，都说明发送缓冲区可能有地方了，让发送线程往下走判断能否发送新数据
    if(sem_post(&sem_event_send_Queue) == -1)
    {
        Logger::write_to_screen("Socket::write_request_handler()调用sem_post()失败");
    }

    memory->free_Memory(pConn->sent_memory_pointer);  //释放发送数据分配的内存
    pConn->sent_memory_pointer = nullptr;

    --pConn->send_count;    //epoll驱动标志位减1，因为需要epoll驱动发送的数据已经发送完了
}


//接收数据
ssize_t Socket::recv_data(connection_pool *pConn, char *buff, ssize_t buf_len)
{
    ssize_t  n;  //记录收到的字节数
    Logger* log = Logger::getInstance();

    //收数据
    n = recv(pConn->fd,buff,buf_len,0);

    if(n == 0)
    {
        //收到字节数等于0，可以看作客户端正常关闭，这边就直接回收连接，关闭socket
        /*if(close(pConn->fd) == -1)
        {
            char info_fmt[128];
            sprintf(info_fmt,"Socket::recv_data()中调用close(%d)失败！",pConn->fd);
            log->write_to_log(ALERT,errno,string(info_fmt));
        }
        //连接正常关闭，把这个连接对象放入延迟回收队列当中
        put_connection_to_Recy_Queue(pConn);*/
        forwardly_close_socket(pConn);  //主动关闭
        return -1;
    }
    if(n < 0)  //返回值小于零，有错误发生
    {
        //EAGAIN和EWOULDBLOCK[【这个应该常用在hp上】应该是一样的值，表示没收到数据
        if(errno == EAGAIN || errno == EWOULDBLOCK)
        {
            Logger::write_to_screen("Socket::recv_data()中errno == EAGAIN || errno == EWOULDBLOCK");
            return -1;
        }
        if(errno == EINTR)  //被信号打断,这里不认为是个错误，返回就可以
        {
            Logger::write_to_screen("Socket::recv_data()中errno == EINTR");
            return -1;
        }
        if(errno == ECONNRESET)
        {
            //如果客户端没有正常关闭socket连接，却关闭了整个运行程序【真是够粗暴无理的，应该是直接给服务器发送rst包而不是4次挥手包完成连接断开】，那么会产生这个错误
            //10054(WSAECONNRESET)--远程程序正在连接的时候关闭会产生这个错误--远程主机强迫关闭了一个现有的连接
            //不做任何事
        } else
        {
            //能走到这里，表示有一些未经捕获的错误，打印看一下
            Logger::write_to_screen("Socket::recv_data()出现了未经捕获的错误");
        }

        //无论上面是任何错误，接下来都是关闭套接字并回收连接对象
        /*if(close(pConn->fd) == -1)
        {
            char info_fmt[128];
            sprintf(info_fmt,"Socket::recv_data()中调用close(%d)失败！",pConn->fd);
            log->write_to_log(ALERT,errno,string(info_fmt));
            return -1;
        }

*/

        forwardly_close_socket(pConn);
        return -1;

    }
    //返回收到的字节数
    return n;
}

//收完完整包头的处理函数
void Socket::after_recv_pkg_header(connection_pool *pConn,bool& isflood)
{
    Memory* memory = Memory::getInstance();
    PKG_HEADER* pkg_header_ptr;
    pkg_header_ptr = (PKG_HEADER*)pConn->header; //正好收完包头时，包头信息肯定在header[]里面，我们使用一个指针指向它

    unsigned short pkg_len;
    pkg_len = ntohs(pkg_header_ptr->pkg_len);  //网络序转本地序,此处是获得整个包的大小

    //接下来是恶意包的判断
    if(pkg_len < pkg_header_len)  //收到的包大小竟然比的包头还小，肯定有问题
    {
        //收到的是个恶意包，所以将参数全部还原
        pConn->pkg_stat = PKG_HD_INIT;
        pConn->ptr_recvbuf = pConn->header;
        pConn->recv_len = pkg_header_len;
    }else if(pkg_len > (PKG_MAX_LENGTH-1000))  //客户端发过来的包的总长度不能大于29000,大于29000就认定恶意包
    {
        //收到的是个恶意包，所以将参数全部还原
        pConn->pkg_stat = PKG_HD_INIT;
        pConn->ptr_recvbuf = pConn->header;
        pConn->recv_len = pkg_header_len;
    } else
    {
        //走下来就收到了合法的包头，开始处理接下的流程，收包体
        //包体大小是不固定，所以这里需要new一块内存,内存的大小是消息头+包长度
        char* tmp_buff = (char*)memory->allocMemory(msg_header_len+pkg_len,false);
        pConn->pkg_memory_pointer = tmp_buff;  //连接对象的收包地址指针赋值

        //填充新分配的内存，先填入消息头
        MSG_HEADER* msg_ptr = (MSG_HEADER*)tmp_buff;
        msg_ptr->conn_pool = pConn;
        msg_ptr->cur_sequence = pConn->current_sequence;

        //再填充包头内容
        tmp_buff += msg_header_len;
        memcpy(tmp_buff,pkg_header_ptr,pkg_header_len);

        if(pkg_len == pkg_header_len)
        {
            //有可能一个包，只有包头，没有包体，这就相当于收了一个完整的包，直接下一步处理
            //整个包正好收完整，并判断没有问题，此处进行flood攻击判断
            if(flood_check_Enable)
            {
                isflood = flood_check(pConn);
            }
            after_recv_full_pkg(pConn,isflood);
        } else
        {
            //如果包还有包体，则开始为收包体准备
            pConn->pkg_stat = PKG_BD_INIT;
            pConn->ptr_recvbuf = tmp_buff + pkg_header_len;
            pConn->recv_len = pkg_len - pkg_header_len;
        }
    }
}

//收到一个完整包之后的处理
void Socket::after_recv_full_pkg(connection_pool *pConn,bool& isflood)
{
    if(!isflood)  //如果认定为非flood攻击
    {
        //把这段保存收到用户消息的内存放到待处理的消息队列当中
        glo_thread_pool.put_msg_to_recvQueue(pConn->pkg_memory_pointer);
    }
    else  //认定为flood攻击，放弃这个包内容
    {
        Memory* memory = Memory::getInstance();
        memory->free_Memory(pConn->pkg_memory_pointer);
    }
    //恢复收包的初始状态。为收下一个包做准备
    pConn->pkg_memory_pointer = nullptr;
    pConn->pkg_stat = PKG_HD_INIT;
    pConn->ptr_recvbuf = pConn->header;
    pConn->recv_len = pkg_header_len;



}

ssize_t Socket::send_data(connection_pool *pConn, char *buff, ssize_t size)
{
    ssize_t n;
    while (true)
    {
        n = send(pConn->fd,buff,size,0);
        if(n > 0)    //成功发送了一些数据 ，返回发送的字节数
            return n;
        if(n == 0)
        {
            //send()返回0表示超时，对方主动断开了连接
            //直接返回0，让上级调用函数处理
            return n;
        }

        if(errno ==EAGAIN)  //表示内核缓冲区已满，需要再试一次
            return -1;
        if(errno == EINTR)  //表示被信号打断，这里不算错误,打印到屏幕上看一下
        {
            Logger::write_to_screen("Socket::send_data()出现EINTR错误");
        } else
        {
            return -2;
        }
    }
}

//清空连接池
void Socket::clear_connection_pool()
{
    connection_pool* pConn;
    Memory* memory = Memory::getInstance();

    while (!connection_list.empty())
    {
        pConn = connection_list.front();
        connection_list.pop_front();
        //pConn->~connection_pool_struct();  不再需要手动调用析构函数，因为我们没有使用posix风格同步机制，所以不再需要在析构函数中销毁锁
        memory->free_Memory(pConn);
    }
}

//将要回收的连接对象放入一个延迟回收队列当中
void Socket::put_connection_to_Recy_Queue(connection_pool *pConn)
{
    bool is_find = false;   //查找标志位，在回收列表中，如果已经回收了某个连接对象，则此标志位为true，主要为了多线程中调用此函数的安全性考量
    std::lock_guard<std::mutex> lock(recycle_conn_list_mutex);

    //遍历回收队列，查找相同连接是否已经放入进来过
    for(auto begin = recycle_conn_list.begin(); begin != recycle_conn_list.end();++begin)
    {
        if((*begin) == pConn)
        {
            is_find = true;
            break;
        }
    }
    if(is_find)        //如果放入进来过，则无需要再操作
    {
        return;
    }


    pConn->recycle_time = time(nullptr);  //记录回收时间
    ++pConn->current_sequence;
    recycle_conn_list.push_back(pConn);
    ++total_recycle_conn_num;
    --onlineUserCount;                 //回收一个连接，我们就将用户连接总数减1;
}

//连接对象的回收线程调用此函数回收连接对象
void* Socket::recy_connection_thread(thread_item *thread_data)
{
    thread_item* p_item = thread_data;
    Socket* p_socket = p_item->p_this;
    time_t currtime;
    connection_pool* pConn;

    std::list<connection_pool*>::iterator begin,end;
    while (true)
    {
        usleep(200*1000); //休息200毫秒
        if(p_socket->total_recycle_conn_num > 0)
        {
            currtime = time(nullptr);
            std::unique_lock<std::mutex> lock(p_socket->recycle_conn_list_mutex);
lblRRTD:
            begin = p_socket->recycle_conn_list.begin();
            end = p_socket->recycle_conn_list.end();
            for(;begin != end;++begin)
            {
                pConn = (*begin);
                if((pConn->recycle_time + p_socket->recycle_wait_time) > currtime && g_stop_pro == 0 )
                {
                    continue;
                }

                //走下来就是到了释放时间了
                if(pConn->send_count > 0)
                {
                    //凡是到了释放时间的，send_count都应该等于0，不等于0，不应该
                    //打印日志看一下
                    Logger::write_to_screen("Socket::recy_connection_thread()中send_cout竟然不等于0！");

                }

                //走下来，表示可以释放，我们着手释放
                --p_socket->total_recycle_conn_num;
                p_socket->recycle_conn_list.erase(begin);
                p_socket->free_connection(pConn);
                goto lblRRTD;
            }
            lock.unlock();
        }

        if(g_stop_pro == 1)  //退出整个程序
        {
            if(p_socket->total_recycle_conn_num > 0)
            {
                //因为程序要退出来，所以这里进行硬释放，不再考虑其他地方的需求
                std::unique_lock<std::mutex> lock(p_socket->recycle_conn_list_mutex);

         lblRRTD2:
                begin = p_socket->recycle_conn_list.begin();
                end = p_socket->recycle_conn_list.end();
                for(;begin != end;++begin)
                {
                    pConn = (*begin);
                    --p_socket->total_recycle_conn_num;
                    p_socket->recycle_conn_list.erase(begin);
                    p_socket->free_connection(pConn);
                    goto lblRRTD2;
                }
                lock.unlock();

            }
            break;
        }
    }
    return (void*)0;

}

//添加连接对象到时间队列当中
void Socket::add_to_Timer_Queue(connection_pool* pConn)
{
    Memory* memory = Memory::getInstance();

    time_t futtime = time(nullptr);    //获取当前时间
    futtime += heartPacket_wait_time;  //当前时间+需要等待的时间

    std::lock_guard<std::mutex> lock(time_queue_mutex);   //互斥

    MSG_HEADER* tmp_msg_header = (MSG_HEADER*)memory->allocMemory(msg_header_len,false);
    tmp_msg_header->conn_pool = pConn;
    tmp_msg_header->cur_sequence = pConn->current_sequence;
    time_Queue.insert(std::make_pair(futtime,tmp_msg_header)); //保存到时间队列当中

    ++time_Queue_size;   //时间队列长度+1
    timer_value = get_Earliest_time();   //计时队列头部时间值保存到timer_value里
}

//从multimap中取得最早的时间返回去，调用者负责互斥，所以本函数不用互斥，调用者确保m_timeQueuemap中一定不为空
time_t Socket::get_Earliest_time()
{
    auto begin = time_Queue.begin();
    return begin->first;
}

//从m_timeQueuemap移除最早的时间，并把最早这个时间所在的项的值所对应的指针返回，调用者负责互斥，所以本函数不用互斥
MSG_HEADER* Socket::remove_first_Timer()
{
    MSG_HEADER* p_msgheader;
    if(time_Queue_size <= 0)
        return nullptr;
    auto begin = time_Queue.begin();
    p_msgheader = begin->second;
    time_Queue.erase(begin);
    --time_Queue_size;
    return p_msgheader;
}

MSG_HEADER* Socket::get_overtime_timer(time_t cur_time)
{
    Memory* memory = Memory::getInstance();
    MSG_HEADER* p_msgheader;

    if(time_Queue_size == 0 || time_Queue.empty())
    {
        return nullptr;
    }

    time_t earliest_time = get_Earliest_time();
    if(earliest_time <= cur_time)
    {
        p_msgheader = remove_first_Timer();

        if(!timeout_kick)   //如果没有开启连接限时功能
        {
            time_t  new_time = cur_time + heartPacket_wait_time;
            MSG_HEADER* tmp_msg_header = (MSG_HEADER*)memory->allocMemory(msg_header_len,false);

            tmp_msg_header->conn_pool = p_msgheader->conn_pool;
            tmp_msg_header->cur_sequence = p_msgheader->cur_sequence;
            time_Queue.insert(std::make_pair(new_time,tmp_msg_header));
            ++time_Queue_size;
        }

        if(time_Queue_size > 0)
        {
            timer_value = get_Earliest_time();
        }
        return p_msgheader;
    }
    return nullptr;

}

void Socket::delete_frome_Time_Queue(connection_pool *pConn)
{
    Memory* memory = Memory::getInstance();
    std::lock_guard<std::mutex> lock(time_queue_mutex);

lblMTQM:
    auto begin = time_Queue.begin();
    auto end = time_Queue.end();

    for(;begin != end;++begin)
    {
        if(begin->second->conn_pool == pConn)
        {
            memory->free_Memory(begin->second);
            time_Queue.erase(begin);
            --time_Queue_size;
            goto lblMTQM;
        }
    }

    if(time_Queue_size > 0)
    {
        timer_value = get_Earliest_time();
    }

}

//清空时间队列所有内容
void Socket::clear_Time_Queue()
{
    Memory* memory = Memory::getInstance();
    for(auto begin = time_Queue.begin();begin != time_Queue.end();++begin)
    {
        memory->free_Memory(begin->second);
        --time_Queue_size;
    }
    time_Queue.clear();
}


void* Socket::time_Queue_Monitor_thread(Socket::thread_item *thread_data)
{
    Socket* p_socket_obj = thread_data->p_this;

    time_t absolute_time,cur_time;

    while (g_stop_pro == 0)
    {
        //这里没互斥判断，所以只是个初级判断，目的至少是队列为空时避免系统损耗
        if(p_socket_obj->time_Queue_size > 0)   //队列不为空
        {
            absolute_time = p_socket_obj->timer_value;   //时间队列中最近发生事情的时间放到 absolute_time里
            cur_time = time(nullptr);
            if(absolute_time < cur_time)
            {
                //时间到了，可以处理了
                std::list<MSG_HEADER*> list_msg;  //保存要处理的内容
                MSG_HEADER* result = nullptr;

                std::unique_lock<std::mutex> lock(p_socket_obj->time_queue_mutex);

                while(result == p_socket_obj->get_overtime_timer(cur_time))   //获取所有到达规定时间的连接
                {
                    list_msg.push_back(result);
                }
                lock.unlock();

                MSG_HEADER* p_tmp_msg;
                while(!list_msg.empty())
                {
                    p_tmp_msg = list_msg.front();
                    list_msg.pop_front();
                    p_socket_obj->ping_timeout_checking(p_tmp_msg,cur_time);
                }


            }
        }
        usleep(500*1000);  //每次都休息500毫秒
    }
    return (void*)0;

}

//心跳包检测时间到，该去检测心跳包是否超时的事宜，本函数只是把内存释放，子类应该重新事先该函数以实现具体的判断动作
void Socket::ping_timeout_checking(MSG_HEADER *p_msg_header, time_t cut_time)
{
    Memory* memory = Memory::getInstance();
    memory->free_Memory(p_msg_header);
}

//主动关闭一个连接时，相应的操作
void Socket::forwardly_close_socket(connection_pool *pConn)
{
    if(if_kick_time_enable == 1)
    {
        delete_frome_Time_Queue(pConn);
    }
    if(pConn->fd != -1)
    {
        close(pConn->fd);
        pConn->fd = -1;
    }
    if(pConn->send_count > 0)
        --pConn->send_count;

    put_connection_to_Recy_Queue(pConn);
}

bool Socket::flood_check(connection_pool *pConn)
{
    auto cur_time = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count(); //获取当前时间的毫秒值
    bool is_kick = false;

    if((cur_time - pConn->flood_kick_last_time) < flood_time_Interval)  //两次收包的时间小于100毫秒，则有flood倾向，统计次数
    {
        ++pConn->flood_attack_count;
        pConn->flood_kick_last_time = cur_time;
    } else
    {
        pConn->flood_attack_count = 0;  //发包不这么频繁，可以恢复计数
        pConn->flood_kick_last_time = cur_time;
    }

    if(pConn->flood_attack_count >= flood_kick_Count)
    {
        is_kick = true;       //到达统计次数，踢人标志位就绪
    }
    return is_kick;

}

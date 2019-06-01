//
// Created by JiangKan on 2019/4/28.
//

#ifndef SIM_SERVER_THREAD_H
#define SIM_SERVER_THREAD_H
#include <mutex>
#include <condition_variable>
#include <atomic>
#include <vector>
#include <thread>
#include <list>

//线程池的实现
class Thread
{
private:

    static std::mutex thread_mutex;                   //互斥量
    static std::condition_variable thread_condition;  //条件变量
    static bool is_down;                              //线程退出标志，false不退出，true退出

    int thread_num;                                   //需要创建多少线程

    std::atomic<int> running_thread_num;              //记录处于运行中的线程数量，此处使用原子操作
    time_t last_emg_time;                             //当线程池线程数量不够用时，会向程序开发者发出警报，这表示发警报的间隔时间，10秒

    struct threadItem                                 //定义一个结构体，用来保存一些关于线程的参数
    {
        std::shared_ptr<std::thread> p_thread;    //线程句柄
        Thread* p_this;   //记录线程池的指针
        bool is_running;  //记录线程是否正式启动起来，只有启动起来后，才允许调用stop_All()释放

        explicit threadItem(Thread* t_this);
        ~threadItem();
    };

    std::vector<threadItem*> thread_container;        //线程容器

    std::list<char*>  msg_recvQueue;
    int msg_count;  //收消息队列大小

    static void* thread_func(threadItem* thread_data);      //新线程的回调函数
    void clear_msg_recvQueue();


public:
    Thread();
    ~Thread();

    bool create_pool(int thread_num);                 //创建线程池
    void stop_All();                                  //关闭并释放所有线程资源
    void call();                             //来消息了，使用些函数来调用线程处理任务
    void put_msg_to_recvQueue(char* buf);                     //把消息放入存储待处理消息队列当中






};



#endif //SIM_SERVER_THREAD_H

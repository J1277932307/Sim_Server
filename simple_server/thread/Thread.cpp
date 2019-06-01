//
// Created by JiangKan on 2019/4/28.
//
#include "../memory/Memory.h"
#include "Thread.h"
#include "../global_value.h"
#include "../log/Logger.h"
#include <chrono>


//静态成员初始化
std::mutex Thread::thread_mutex;
std::condition_variable Thread::thread_condition;
bool Thread::is_down = false;

//threadItem构造函数和析构函数
Thread::threadItem::threadItem(Thread *t_this):p_this(t_this),is_running(false)
{
    p_thread.reset(new std::thread(&Thread::thread_func,this));            //这里的this是指threadItem
};
Thread::threadItem::~threadItem() {};


//Thread类函数的实现
Thread::Thread()
{
    running_thread_num = 0;    //正在处理任务的线程数
    last_emg_time = 0;         //当线程池线程数量不够用时，会向程序开发者发出警报，这表示发警报的间隔时间
    msg_count = 0;   //消息队列当中的消息数量
}
Thread::~Thread()
{
    clear_msg_recvQueue();
}

//清空收消息队列
void Thread::clear_msg_recvQueue()
{
    //收尾阶段，线程该退都退了，不需要互斥
    char* tmp_mem_pointer;
    Memory* memory = Memory::getInstance();
    while (!msg_recvQueue.empty())
    {
        tmp_mem_pointer = msg_recvQueue.front();
        msg_recvQueue.pop_front();
        memory->free_Memory(tmp_mem_pointer);
    }
}

//创建线程池，或者更准确来说，是创建线程池中的线程，thread_num表示需要创建的线程个数
bool Thread::create_pool(int thread_num)
{
    //threadItem* p_newItem;
    int err;

    this->thread_num = thread_num;     //保存要创建的线程数量

    for(int i = 0;i < this->thread_num; ++i)
    {
        thread_container.push_back(new threadItem(this));
    }

    //接下来遍历一下，确认整个线程池的线程是否全部启动起来
    std::chrono::milliseconds millsecond(100);

    lblfor:
    for(auto begin = thread_container.begin();begin != thread_container.end();++begin)
    {
        if( (*begin)->is_running == false)
        {
            //如果线程还没有准备就绪，就等它100毫秒
            std::this_thread::sleep_for(millsecond);

            //这里用到了goto，好像这还是我第一次用goto
            //从头再遍历一次
            goto lblfor;
        }
    }
    return true;
}

void* Thread::thread_func(Thread::threadItem *thread_data)
{
    threadItem* p_item = thread_data;
    Thread* p_pool = p_item->p_this;

    char* jobbuf = nullptr;
    Memory* memory = Memory::getInstance();


    std::thread::id thread_id = std::this_thread::get_id();      //获取进程id

    while (true)
    {
        std::unique_lock<std::mutex> lock(thread_mutex);  //加锁


        //注意这个while的写法，当消息队列为空，且线程池为正常运行的，我们就wait在这个while当中，只有当取出消息时，即消息队列中有消息了，判断!NULL，才正常走到下面去
        while ((p_pool->msg_recvQueue.size() == 0) && is_down == false)
        {
            //当程序运行时，消息队列为空，所以所有线程池的线程都会走到这里，然后我们把它的is_running设为true，标志线程被正式启动起来
            if(p_item->is_running == false)
            {
                p_item->is_running = true;
            }

            //程序启动伊始，所以线程都会卡在这里，等待消息队列有数据后被notify_*唤醒，具体是唤醒一个还是唤醒所有，我们后面再考量
            thread_condition.wait(lock);
        }





        //能走下来，说明拿到了消息队列中的信息或是is_down==true，即线程池将要终止
        //接下来先判断线程池的退出条件
        if(is_down)
        {
            //如果我们取到了消息，但是is_down标志置1
            lock.unlock();
            break;
        }

        //走到这里，就可以进行消息处理，且消息队列当中必然有消息
        jobbuf = p_pool->msg_recvQueue.front();
        p_pool->msg_recvQueue.pop_front();
        --p_pool->msg_count;

        //取完消息就可以解锁互斥量了
        lock.unlock();
        ++p_pool->running_thread_num;   //工作中进程数量加1
        glo_socket.thread_recv_proc_func(jobbuf);  //线程调用消息处理函数进行消息处理
        memory->free_Memory(jobbuf);   //消息处理完毕后，清除为消息分配的内存
        --p_pool->running_thread_num;  //活动状态线程减1




    }
    //能走到这里，表示整个程序都要结束了
    return (void*)0;




}

//调用一个线程开始接收任务
void Thread::call()
{
    //如果线程池用尽了，这里唤醒会有什么后果呢，好像是notify_one()即没有出错返回值，也声明不会出现异常
    thread_condition.notify_one();

    //如果线程池总量和运行线程的总量相等，即整个线程池的线程都用尽了
    if(thread_num == running_thread_num)
    {
        //获取当前时间
        time_t current_time = time(nullptr);
        if(current_time - last_emg_time > 10)  //最少间隔十秒报错
        {
            last_emg_time = current_time;
            Logger::write_to_screen("Thread线程池的线程用尽，需要考虑扩容线程池");
        }


    }


}

//停止所有线程池中的线程
void Thread::stop_All()
{
    if(is_down == true)  //如果此线程调用过这个函数，则无需处理
        return;
    is_down = true;
    thread_condition.notify_all();  //唤醒所有沉睡中的线程

    for(auto begin = thread_container.begin();begin != thread_container.end();++begin)
    {
        //让主进程等待每一个线程终止
        (*begin)->p_thread->join();
    }
    //走下来，就说明所有线程都返回了，依次释放threadItem
    for(auto begin = thread_container.begin();begin != thread_container.end();++begin)
    {
        if(*begin)
        {
            delete (*begin);
        }
    }
    thread_container.clear();
    Logger::write_to_screen("Thread::stop_All()成功返回，线程池中线程全部正常线束！");
}

//收到一个完整的包，入消息队列，并触发线程池中的线程来处理该消息
void Thread::put_msg_to_recvQueue(char* buf)
{
    std::unique_lock<std::mutex> lock(thread_mutex);  //获取线程锁
    msg_recvQueue.push_back(buf);
    ++msg_count;  //消息列队中消息数量+1
    lock.unlock();
    call();       //调用线程来干活


}

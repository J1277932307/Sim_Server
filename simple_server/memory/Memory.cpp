//
// Created by JiangKan on 2019/4/13.
//

#include <cstring>
#include "Memory.h"

Memory* Memory::memory = nullptr;
//std::mutex Memory::mutex;

Memory::Memory(){};

Memory::~Memory(){};
Memory* Memory::getInstance()
{
    if(memory == nullptr)
    {
        // mutex.lock();
        if(memory == nullptr)
        {
            memory = new Memory();
            static Mem_CG cg;
        }
        //mutex.unlock();

    }
    return memory;
}

void* Memory::allocMemory(int memCount, bool is_memset)
{
    void* tempData = (void*)new char[memCount];

    //这里判断是不是需要填充为0，默认为true
    if(is_memset)
    {
        memset(tempData,0,memCount);
    }
    return tempData;
}

void Memory::free_Memory(void *point)
{
    delete [] ((char*)point);  //new的时候就char* 这里再转换成char*，否则会出警告
}
//
// Created by JiangKan on 2019/4/22.
//

#ifndef SIM_SERVER_MEMORY_H
#define SIM_SERVER_MEMORY_H


//这是一个单例类
class Memory
{
private:
    //私有化构造函数
    Memory();
    //static std::mutex mutex;
    static Memory* memory;

public:

    static Memory* getInstance();
    ~Memory();
    void *allocMemory(int memCount,bool is_memset = true);
    void free_Memory(void *point);



    class Mem_CG
    {
    public:
        ~Mem_CG()
        {
            if(Memory::memory)
            {
                delete Memory::memory;
                Memory::memory = nullptr;
            }
        }
    };

};

#endif //SIM_SERVER_MEMORY_H

//
// Created by JiangKan on 2019/4/30.
//

#ifndef SIM_SERVER_CRC32_H
#define SIM_SERVER_CRC32_H


class CRC32
{
private:
    static CRC32* crc;   //标准单例类
    CRC32();

public:
    ~CRC32();
    static CRC32* getInstance();
    void init_CRC32_table();
    unsigned int reflect(unsigned int ref,char ch);
    int get_CRC(unsigned char* buffer,unsigned int dsSize);
    unsigned int crc32_table[256];

    CRC32(const CRC32 &c) = delete;
    CRC32& operator=(const CRC32 &c) = delete;

    class CG_crc
    {
    public:
        ~CG_crc()
        {
            if(CRC32::crc)
            {
                delete CRC32::crc;
                CRC32::crc = nullptr;
            }
        }
    };
};


#endif //SIM_SERVER_CRC32_H

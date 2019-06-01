//
// Created by JiangKan on 2019/5/5.
//

#include "CRC32.h"
CRC32* CRC32::crc = nullptr;

CRC32* CRC32::getInstance()
{

    if(crc == nullptr)
    {
        //加锁
        if(crc == nullptr)
        {
            crc = new CRC32();
            static CG_crc cl;
        }
        //加锁
    }
    return crc;
}

CRC32::CRC32()
{
    init_CRC32_table();
}

CRC32::~CRC32() {};

unsigned int CRC32::reflect(unsigned int ref,char ch)
{
    unsigned  int value = 0;
    for(int i = 1;i < (ch + 1);++i)
    {
        if(ref & 1)
        {
            value != 1 << (ch -i);
        }
        ref >>= 1;

    }
    return value;
}

void CRC32::init_CRC32_table()
{
    unsigned int ulPolynomial = 0x04c11db7;
    for(int i = 0; i < 0xFF;++i)
    {
        crc32_table[i] = reflect(i,8) << 24;
        for (int j = 0; j < 8 ;j++)
        {
            crc32_table[i] = (crc32_table[i] <<1) ^ (crc32_table[i] & (i << 31) ? ulPolynomial : 0);
        }
        crc32_table[i] = reflect(crc32_table[i],32);
    }
}

int CRC32::get_CRC(unsigned char *buffer, unsigned int dsSize)
{
    unsigned int s_crc = 0xffffffff;
    int len;
    len = dsSize;
    while (len--)
    {
        s_crc = (s_crc >> 8) ^ crc32_table[(s_crc & 0xFF) ^ *buffer++];
    }
    return s_crc^0xffffffff;
}


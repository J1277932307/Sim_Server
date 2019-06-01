//
// Created by JiangKan on 2019/4/20.
//

#include "utils.h"
#include <unistd.h>
#include <chrono>
#include <time.h>

using namespace std;

//去除字符串两端的空格
std::string trim(std::string s)
{
    if (s.empty())
    {
        return s;
    }

    s.erase(0,s.find_first_not_of(' '));

    s.erase(s.find_last_not_of(' ') + 1);

    //去除字符串末尾\r符，因为windows上换行是以\r\n换行的，getline()会自动去除\n，但\r需要我们手动去除，如果在linux上则不用如此
    s.erase(s.find_last_not_of('\r')+1);
    return s;
}

//格式化输出时间
string str_time()
{
    char timebuff[64];

    time_t t = chrono::system_clock::to_time_t(chrono::system_clock::now());
    tm* tt = localtime(&t);
    strftime(timebuff,63,"%Y/%m/%d %H:%M:%S",tt);

    return string(timebuff);
}
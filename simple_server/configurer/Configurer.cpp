//
// Created by JiangKan on 2019/3/19.
//

#include "Configurer.h"
#include <fstream>
#include <iostream>
#include <string>
#include "../util/utils.h"

using namespace std;

//定义一个外部的flgs，切记不能定义在函数内部

//初始化static 成员
Configurer* Configurer::config_ptr = nullptr;

//构造函数
Configurer::Configurer() {};


Configurer::~Configurer() {};


Configurer* Configurer::getInstance()
{
    //单例模式

    /* call_once(flags,[](){
         config_ptr = new Configurer();
         config_ptr->config_load("../server.conf");
 
         static CG cg;
     });*/
    if(config_ptr == nullptr)
    {
        config_ptr = new Configurer();
        config_ptr->config_load("server.conf");

        static CG cg;
    }
    return config_ptr;
}


//加载配置文件方法
bool Configurer::config_load(const string &config_file_path)
{
    fstream file;
    file.open(config_file_path,fstream::in);
    if(!file.is_open())
    {
        cout << "配置文件加载失败，直接终止进程"<<endl;
        exit(-1);
    }
    string line;
    while (getline(file,line))
    {

        if(line[0] == '[')
            continue;
        if(line[0] == '#')
            continue;
        if(line.empty())
            continue;
        if(line == "\r")
            continue;

        size_t pos = line.find('=');
        if(pos == string::npos)
            return false;


        string key = trim(line.substr(0,pos));

        string Value = trim(line.substr(pos+1));

        config_store.insert({key,Value});
    }



    file.close();



    return true;







}

string Configurer::get_config_by_name(const string &conf_name)
{
    if(config_store.find(conf_name) != config_store.end())
    {
        return config_store[conf_name];

    } else
    {
        return "";
    }

}

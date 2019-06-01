//
// Created by JiangKan on 2019/4/20.
//

#ifndef SIM_SERVER_CONFIGURER_H
#define SIM_SERVER_CONFIGURER_H


#include <memory>
#include <map>
#include <vector>


using std::map;
using std::string;





class Configurer
{
private:
    static Configurer* config_ptr;
    map<string,string> config_store;

    //构造函数私有化，单例模式
    Configurer();

public:

    static Configurer* getInstance();
    Configurer(const Configurer&) = delete;
    Configurer& operator=(const Configurer&) = delete;
    bool config_load(const string& config_file_path);
    string get_config_by_name(const string& conf_name);

    ~Configurer();

    //使用类中类释放资源
    class CG
    {
    public:
        ~CG()
        {
            if(Configurer::config_ptr)
            {
                delete Configurer::config_ptr;
                Configurer::config_ptr = nullptr;
            }
        }
    };


};


#endif //SIM_SERVER_CONFIGURER_H

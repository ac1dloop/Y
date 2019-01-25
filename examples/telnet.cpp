#include "socket.h"

#include <thread>
#include <string>
#include <iostream>
#include <functional>
#include <algorithm>
#include <vector>

using namespace std;

struct Telnet {

    Telnet(const std::string& addr, uint16_t port, function<string(string)> cb):m_sock(addr, port), worker(cb){
        m_sock.Bind();
        m_sock.Listen();
        m_thread=thread(&Telnet::main_loop, this);
    }

    ~Telnet(){
        cout << "destructor" << endl;

        if (m_thread.joinable())
            m_thread.join();
    }

private:

    void main_loop(){
        for (;;){

            Y::TCPSocket<Y::ipv4> client=m_sock.Accept();

            thread t(&Telnet::process_connection, this, client);
            t.detach();
        }
    }

    void process_connection(Y::TCPSocket<Y::ipv4> sock){
        for (;;){
            string msg=sock.read();

            if (msg.empty())
                break;

            sock.write(Util::str_to_nvt(worker(Util::nvt_to_str(msg))));
        }

        sock.Close();
    }

    function<string(string)> worker;
    Y::TCPSocket<Y::ipv4> m_sock;
    thread m_thread;
};

struct History {

    History()=default;

private:
    vector<string> data;
    function<string(string)> func{ [this](string str){
            string res;
            if (str=="hello"){
                for (auto x: data)
                    res+=x;
            } else {
                data.push_back(str);
            }

        return res;
    } };
    Telnet srv{"0.0.0.0", 9999, func};
};

int main(int argc, char *argv[])
{
    auto func=[](string str){
        if (str=="hello")
            return string("world");
        else {
            reverse(str.begin(), str.end());
            return str;
        }
    };

//    Telnet srv("0.0.0.0", 9999, func);

    History hist;

    return 0;
}

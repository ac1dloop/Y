#include <iostream>
#include "include/socket.hpp"
#include <cstring>

using namespace std;
using namespace Y;

static std::vector<ip4_addr> getAddrByName(const string& hostname, socktype t, const string& service_or_port){
    std::vector<ip4_addr> res;

    addrinfo hints, *result;
    addrinfo *it;

    memset(&hints, 0, sizeof(hints));

    hints.ai_family=ipv4;
    hints.ai_socktype=t;
    hints.ai_flags=AI_CANONNAME;

    int ret=getaddrinfo(hostname.c_str(), service_or_port.c_str(), &hints, &result);
    if (ret!=0){
        throw std::logic_error(gai_strerror(ret));
    }

    for (it=result;it!=nullptr;it=it->ai_next){
        res.emplace_back(*reinterpret_cast<sockaddr_in*>(it->ai_addr));
    }

    freeaddrinfo(result);

    return res;
}

static std::vector<std::string> getNameByAddr(const string& addr, socktype t, const string& service_or_port){
    std::vector<std::string> res;
    ip4_addr add(addr.c_str(), 0);

    addrinfo hints, *result;
    addrinfo *it;

    memset(&hints, 0, sizeof(hints));

    hints.ai_family=ipv4;
    hints.ai_socktype=t;
    hints.ai_addr=&add;
    hints.ai_flags=AI_CANONNAME;

    int ret=getaddrinfo(nullptr, service_or_port.c_str(), &hints, &result);
    if (ret!=0){
        throw std::logic_error(gai_strerror(ret));
    }

    for (it=result;it!=nullptr;it=it->ai_next){
        res.emplace_back(it->ai_canonname);
    }

    freeaddrinfo(result);

    return res;
}

int main(int argc, char *argv[])
{
//    auto vec=getAddrByName(argv[1], socktype::stream, "http");

//    for (auto x: vec){
//        cout << "addr: " << x.Addr() << " port: " << x.Port() << '\n';
//    }

    auto names=getNameByAddr(argv[1], socktype::stream, "ftp");

    for (auto x: names){
        cout << "name: " << x << '\n';
    }

    return 0;
}

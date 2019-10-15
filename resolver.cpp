#include <iostream>
#include "include/socket.hpp"
#include <cstring>

using namespace std;
using namespace Y;

int main(int argc, char *argv[])
{
    auto vec=getAddrByName(argv[1], socktype::stream, argv[2]);

    for (auto x: vec){
        cout << "addr: " << x << '\n';
    }

//    auto names=getNameByAddr(argv[1], socktype::stream, atoi(argv[2]));

//    for (auto x: names){
//        cout << "name: " << x << '\n';
//    }

    return 0;
}

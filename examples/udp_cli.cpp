#include <iostream>
#include <socket.h>

using namespace std;
using namespace Y;

int main(int argc, char *argv[])
{
    if (argc!=3){
        cout << "usage " << argv[0] << " [host] [port]\n";
        return -1;
    }

    Socket<family::ipv4, socktype::datagram> sock(argv[1], atoi(argv[2]));

    string str;
    for (;;){
        cin >> str;

        sock.sendStr(str);
    }

    return 0;
}

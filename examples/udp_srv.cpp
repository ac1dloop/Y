#include <iostream>
#include <socket.hpp>

using namespace std;
using namespace Y;

int main(int argc, char *argv[])
{
    Socket<family::ipv4, socktype::datagram> sock("0.0.0.0", 9999);

    sock.Bind();

    string str;
    for (int i=0;i<100;++i){
        msg_host4 msg=sock.recvStrOnce();

        cout << "recvd: " << msg.first << "\n";
        cout << "from: " << msg.second.Addr() << " " << msg.second.Port() << "\n";

        sock.sendStr(std::to_string(i), msg.second);
    }

    return 0;
}

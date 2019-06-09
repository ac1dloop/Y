#include <iostream>
#include <socket.h>
#include <thread>

using namespace std;
using namespace Y;

using TCPSocket4 = Socket<family::ipv4, socktype::stream>;
using TCPSocket6 = Socket<family::ipv6, socktype::stream>;

void process_conn(TCPSocket6 sock){
    std::string str;

    for (;sock.state;){
        str=sock.readStr("\r\n");

        if (str.empty())
            break;

        sock.writeStr(str);
    }

    cout << "closed connection\n";

    sock.Close(2);
}

int main(int argc, char *argv[])
{
    TCPSocket6 sock("::", 9999);

    sock.Bind();
    sock.Listen();

    for (;sock.state;){
        TCPSocket6 client=sock.Accept();

        thread t(process_conn, client);
        if (t.joinable())
            t.detach();
    }

    sock.Shutdown();

    return 0;
}

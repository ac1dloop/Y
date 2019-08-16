#include <iostream>
#include <socket.hpp>
#include <thread>

using namespace std;
using namespace Y;

using TCPSocket4 = Socket<family::ipv4, socktype::stream>;
using TCPSocket6 = Socket<family::ipv6, socktype::stream>;

void process_conn(UnixTCPSocket sock){
    std::string str;

    for (;sock.state;){
        str=sock.readStr("\r\n");

        if (str.empty())
            break;

        cout << "recvd: " << str.substr(0, str.size()-2) << "\n";

        sock.writeStr(str);
    }

    cout << "closed connection\n";

    sock.Close();
}

int main(int argc, char *argv[])
{
//    TCPSocket4 sock("0.0.0.0", 9999);
    UnixTCPSocket sock("/tmp/inter.sock");

    try {
        sock.Bind();
        sock.Listen();
    } catch (std::exception& e){
        cout << e.what() << "\n";
    }

    for (;sock.state;){
//        TCPSocket4 client=sock.Accept();
        auto client = sock.Accept();

        thread t(process_conn, client);
        if (t.joinable())
            t.detach();
    }

    sock.Close();

    return 0;
}

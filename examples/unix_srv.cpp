#include <iostream>
#include <socket.hpp>

using namespace std;
using namespace Y;

void process_conn(UnixTCPSocket sock){
    std::string str;

    for (;sock.state;){
        try {
            str=sock.readStr("\r\n");
        } catch (std::exception& e){
            cout << "error: " << e.what() << '\n';
            break;
        }

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
//    if (argc!=2){
//        cout << "usage " << argv[0] << " [pathname]\n";
//        return -1;
//    }

    TCPSocket4 s1("0.0.0.0", 10001);
    UnixTCPSocket sock("/tmp/mtusrv.sock");

    cout << "using path: " << sock.Path() << endl;

//    try {
        sock.Bind();
        sock.Listen();
//    } catch (std::exception& e){
//        cout << e.what() << "\n";
//    }

    for (;sock.state;){
        auto client=sock.Accept();

        thread t(process_conn, client);
        if (t.joinable())
            t.detach();
    }

    sock.Close();

    return 0;
}

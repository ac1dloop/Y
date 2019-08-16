#include <iostream>
#include <socket.hpp>

using namespace std;
using namespace Y;

int main(int argc, char *argv[])
{
    if (argc!=2){
        cout << "usage " << argv[0] << " [pathname]\n";
        return -1;
    }

    UnixTCPSocket sock(argv[1]);

    sock.Connect();

    string str;
    for (;;){
        cin >> str;
        str+="\r\n";

        sock.writeStr(str);

//        cout << "reply: " << sock.readStr("\r\n");
    }

    return 0;
}

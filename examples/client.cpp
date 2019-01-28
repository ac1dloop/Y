#include <iostream>
#include "../socket.h"

using namespace std;

int main(int argc, char **argv)
{
    uint16_t port;
    string ip_addr;

    if (argc<3){
        cout << "usage " << argv[0] << " [ip_addr] [port]" << endl;
        return 1;
    }

    port=atoi(argv[2]);

    Y::TCPSocket<Y::ipv4> sock(argv[1], port);

    string line;

    sock.Connect();

    cout << "Connected to Server" << endl;

    for (;;){
//        cin.ignore(std::numeric_limits<size_t>::max());
        std::getline(cin, line, '\n');

//        sock.write(Util::str_to_nvt(line));
        sock << line;

//        line=Util::nvt_to_str(sock.read());
        sock >> line;

        cout << "response: " << line << endl;
    }

    sock.Close();

    return 0;
}

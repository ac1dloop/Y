#include "../socket.h"

#include <iostream>

using namespace std;
using namespace Y;
using namespace Util;

int main(int argc, char *argv[])
{
    if (argc<3){
        cout << "usage " << argv[0] << " [addr] [port]" << endl;
        return 1;
    }

    try {
        UDPSocket<ipv4> sock;

        string msg="hello";
        ip_addr<ipv4> multi(argv[1], atoi(argv[2]));

        sock.send(str_to_nvt("hello"), multi);

        cout << "done" << endl;

    } catch (Err& e){
        cout << e.strErr() << endl;
    }

    return 0;
}

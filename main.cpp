#include <iostream>
#include "socket.h"

using namespace Y;
using namespace Util;
using namespace std;

int main()
{
    TCPSocket<ipv4> sock1("127.0.0.1", 9999);
    TCPSocket<ipv4> sock2("192.168.1.1", 2345);

    TCPSocket<ipv6> sock3("::1", 9999);
    TCPSocket<ipv6> sock4("2001:0db8:85a3:0000:0000:8a2e:0370:7334", 1234);

    sock2=sock1;
    sock4=sock3;

    cout << sock4.Addr() << ":" << sock4.Port() << endl;

    return 0;
}

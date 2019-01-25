#include <iostream>
#include "socket.h"

using namespace Y;
using namespace Util;
using namespace std;

int main()
{
    TCPSocket<ipv4> sock("0.0.0.0", 9999);

    sock.Bind();

    sock.Listen();

    for (int i=0;i<3&&sock.state;++i){

        TCPSocket<ipv4> client=sock.Accept();

        string msg;

        for (;client.state;){
            client >> msg;

            cout << "recvd: " << msg << endl;
        }

        client.Close();
    }

    sock.Close();

    return 0;
}

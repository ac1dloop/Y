#include <iostream>
#include "socket.h"

using namespace std;

int main(int argc, char *argv[])
{
    uint16_t port=9999;
    if (argc==2)
        port=std::atoi(argv[1]);

    Y::TCPSocket<Y::ipv4> sock("127.0.0.1", port);

    sock.Bind();
    sock.Listen();

    for (;;){

        Y::TCPSocket<Y::ipv4> client=sock.Accept();

        cout << client.Addr() << ":" << client.Port() << " connected" << endl;

        string input="";

        for (;input!="exit";){

            /* operator >> automatically applies and removes CRLF when reading\writing */

            client >> input;

            cout << "recvd: " << input << endl;

            client << input;
        }

        client.Close();
    }

    sock.Close();

    return 0;
}

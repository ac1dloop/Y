#include <iostream>
#include "../socket.h"

using namespace Y;
using namespace Util;
using namespace std;

/* echo server that listening on both ipv4 and ipv6 */

int main()
{
    /* create v4 socket */

    TCPSocket<ipv4> sock("0.0.0.0", 9999);

    /* or v6 */

    TCPSocket<ipv6> sock6("::1", 10101);

    sock.Bind();
    sock.Listen();

    sock6.Bind();
    sock6.Listen();

    /* ipv4 thread */

    thread t1=thread([&](){
        for (int i=0;i<3&&sock.state;++i){

            TCPSocket<ipv4> client=sock.Accept();

            string msg;

            /* bool state is true if socket is ok
             * and false otherwise */

            for (;client.state;){

                /* operator << automatically applies CRLF *
                 * operator >> automatically removes CRLF */

                client >> msg;

                cout << "recvd: " << msg << endl;

                client << msg;
            }

            client.Close();
        }

        sock.Close();
    });

    thread t2=thread([&](){
        for (int i=0;i<3&&sock6.state;++i){

            TCPSocket<ipv6> client6=sock6.Accept();

            string msg;

            for (;client6.state;){
                client6 >> msg;

                cout << "recvd: " << msg << endl;

                client6 << msg;
            }

            client6.Close();
        }

        sock6.Close();
    });

    t1.join();
    t2.join();

    return 0;
}

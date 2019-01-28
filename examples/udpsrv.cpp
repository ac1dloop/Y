#include "../socket.h"

#include <iostream>
#include <future>

using namespace std;
using namespace Y;
using namespace Util;

int main(int argc, char *argv[])
{
    uint16_t port;
    int id;

    if (argc==3){
        port=atoi(argv[1]);
        id=atoi(argv[2]);
    } else {
        cout << "usage " << argv[0] << " [port] [id]" << endl;
        return 1;
    }

    try {
        UDPSocket<ipv4> sock("0.0.0.0", port);
        msg_host4 msg;

        sock.Bind();

        for (int i=0;i<5;++i){
            msg=sock.receive();

            cout << "recvd: " << nvt_to_str(msg.first) << endl;
        }

        sock.Close();
    } catch (Err& e){
        cout << e.strErr() << endl;
    }

    return 0;
}

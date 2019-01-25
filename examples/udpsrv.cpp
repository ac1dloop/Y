#include "socket.h"

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

        for (;;){
            msg=sock.receive();

            cout << "recvd: " << nvt_to_str(msg.first) << endl;
//            std::future<msg_host4> fut(async(launch::async, [&](){
//                return sock.receive();
//            }));

//            if (fut.wait_for(chrono::seconds(2))==future_status::timeout){
//                cout << "timeout" << endl;
//                goto sen;

//            } else {

//                msg=fut.get();

//                cout << "received message from " << msg.second.Addr() << ":" << msg.second.Port();
//                cout << " message: " << nvt_to_str(msg.first) << endl;
//            }

//            sen:
//            sock.send(str_to_nvt(std::to_string(id)), multi);

//            cout << "sent message" << endl;

//            this_thread::sleep_for(chrono::seconds(2));
        }

        sock.Close();
    } catch (Err& e){
        cout << e.strErr() << endl;
    }

    return 0;
}

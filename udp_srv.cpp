#include "include/socket.hpp"
#include <iostream>

using namespace Y;
using namespace std;

int main(int argc, char **argv)
{
	UDPSocket4 sock("0.0.0.0", 10101);

	sock.Bind();
	
	for (;sock.state;){
        auto msg=sock.recvData(4);
//		auto msg=sock.recvStr("\r\n");

//		cout << "recvd: " << msg.first.substr(0, msg.first.size()-2) << '\n';
        cout << "recvd: ";
        for (auto x: msg.first){
            cout << hex << (int)x << ' ';
        }
        cout << '\n';
        cout << "from: " << msg.second.Addr() << ':' << dec << msg.second.Port() << '\n';

//		sock.sendStr(msg.first, msg.second);
	}

	return 0;
}

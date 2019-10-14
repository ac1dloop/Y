#include "include/socket.hpp"
#include <iostream>

using namespace std;
using namespace Y;

int main(int argc, char **argv)
{
	if (argc!=2){
		cout << "usage " << argv[0] << " [socket]\n";
		return -1;	
	}

    UnixUDPSocket sock(argv[1]);

    sock.Bind();

	for (;sock.state;){
		auto msg=sock.recvStr("\r\n");

		cout << "text: " << msg.first.substr(0, msg.first.size()-2) << '\n';
		cout << "from: " << msg.second.Path() << '\n';

		sock.sendStr(msg.first, msg.second);
	}

	sock.Close();

	return 0;
}

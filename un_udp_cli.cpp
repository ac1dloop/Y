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

	char buff[L_tmpnam];
	tmpnam(buff);

	UnixUDPSocket sock(buff);
	sock.Bind();

	std::thread th([&sock](){
			for (;;){
				auto msg=sock.recvStr("\r\n");

				cout << "text: " << msg.first.substr(0, msg.first.size()-2) << '\n';
				cout << "from: " << msg.second.Path() << '\n';
			}
			});
	if (th.joinable())
		th.detach();

	ip_addr<family::local> addr(argv[1]);

	for (;sock.state;){
		string s;
		cin >> s;

		sock.sendStr(s+"\r\n", addr);
	}

	sock.Close();

	return 0;
}

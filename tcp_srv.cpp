#include "include/socket.hpp"
#include <iostream>

using namespace std;
using namespace Y;

void process_connection(TCPSocket4 sock){
	cout << "processing connection with client " << sock.Addr() << ':' << sock.Port() << '\n';

	for (;sock.state;){
		string s=sock.readStr("\r\n");

		cout << "recvd: " << s.substr(0, s.size()-2) << '\n';
		
		sock.writeStr(s);
	}
	
	sock.Close();
}

int main(int argc, char **argv)
{
	if (argc!=3){
		cout << "usage " << argv[0] << " [ip] [port]\n";
		return -1;	
	}

	TCPSocket4 sock(argv[1], atoi(argv[2]));

    sock.Bind();
	sock.Listen();

	for (;sock.state;){
		TCPSocket4 client=sock.Accept();

		std::thread th(process_connection, client);
		if (th.joinable())
			th.detach();
	}

	sock.Close();

	return 0;
}

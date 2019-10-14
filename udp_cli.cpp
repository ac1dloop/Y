#include "include/socket.hpp"
#include <iostream>

using namespace Y;
using namespace std;

int main(int argc, char **argv)
{
	if (argc != 3){
		cout << "usage " << argv[0] << " [ip] [port]\n";
		return -1;
	}
    UDPSocket4 sock(argv[1], atoi(argv[2]));
//	ip_addr<family::ipv4> addr(argv[1], atoi(argv[2]));
    sock.Connect(std::chrono::seconds(5));
	
    uint32_t val=0;
    std::vector<uint8_t> vec(sizeof(val));
	for (;sock.state;){
        ++val;
        memcpy(vec.data(), &val, sizeof(val));

//        sock.sendData(vec, addr);
        sock.sendData(vec);

        std::this_thread::sleep_for(std::chrono::milliseconds(200));
	}

	return 0;
}

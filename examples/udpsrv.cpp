#include <iostream>
#include "../socket.h"

using namespace std;
using namespace Y;

int main(int argc, char *argv[])
{
    uint16_t port;
    string addr;

    if (argc<3){
        cout << "usage " << argv[0] << " [ip-address] [port]" << endl;
        return 1;
    }

    addr.append(argv[1]);
    port=atoi(argv[2]);



    return 0;
}

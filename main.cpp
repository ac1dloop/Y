#include <iostream>
#include "socket.h"

using namespace Y;
using namespace Util;
using namespace std;

int main()
{
    try {
        throw SocketException<ErrTypes::io>();
    } catch (E& e){
        cout << e.strErr() << endl;
    }

    return 0;
}

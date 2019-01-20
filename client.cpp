#include <iostream>
#include "socket.h"

#include <fstream>

using namespace std;
using namespace Y;
using namespace Util;

int main(int argc, char **argv)
{
    TCPSocket<ipv6> sock("::1", 9999);

    sock.Connect();

    for (;;){
        string str;
        std::getline(cin, str);

        if (str.substr(0, str.find(' '))=="file"){
            string filename=str.substr(str.find(' ')+1, str.size()-str.find(' '));
            cout << "sending file " << filename << " " << filename.size() << endl;

            str_to_nvt(str);
            sock.write(str);

            fstream in;

            in.open(filename, ios_base::in | ios_base::binary);

            if (!in)
                cout << "cannot open file" << endl;

            this_thread::sleep_for(chrono::seconds(3));

            TCPSocket<ipv6> srv_sock("::1", 12201);

            in.seekg(0, ios_base::end);
            uint32_t filesize=in.tellg();
            cout << "filesize " << filesize << endl;
            in.seekg(0, ios_base::beg);

            char *buff=new char[filesize];

            in.read(buff, filesize);

            srv_sock.Connect();

            cout << "Connected to 12201" << endl;

            filesize=htonl(filesize);

            srv_sock.writePOD((char*)&filesize, sizeof(uint32_t));
            srv_sock.writePOD(buff, filesize);

            delete[] buff;

            srv_sock.Close();
        } else {
            str_to_nvt(str);

            sock.write(str);

            str=sock.read();

            nvt_to_str(str);

            cout << "recvd: " << str << endl;
        }
    }

    return 0;
}

#include <iostream>
#include "socket.h"
#include <fstream>

using namespace std;
using namespace Y;
using namespace Util;

int main(int argc, char *argv[])
{
    uint16_t port=9999;
    std::string str;

    TCPSocket<ipv6> sock;

    sock.Bind("::1", port);

    sock.Listen();

    for (;;){
        TCPSocket<ipv6> client=sock.Accept();
        cout << "client: " << client.Addr() << ":" << client.Port() << endl;

        for (;;){
            str=client.read();

            if (str.empty())
                break;

            nvt_to_str(str);

            cout << "recvd: " << str << endl;

            if (str=="exit")
                break;

            if (str.substr(0, 4)=="file"){
                string filename=str.substr(str.find(' ')+1, str.size());
                uint32_t filesize=0;
                fstream out;

                cout << "filename " << filename << endl;

                out.open(filename, ios_base::binary | ios_base::out);

                if (!out)
                    cout << "cannot open " << filename << endl;

                TCPSocket<ipv6> file_sock;

                file_sock.Bind("::1", 12201);

                file_sock.Listen();

                TCPSocket<ipv6> client_file_sock=file_sock.Accept();

                client_file_sock.readPOD((char*)&filesize, sizeof(uint32_t));

                filesize=ntohl(filesize);

                cout << "filesize " << filesize << endl;

                char *buff=new char[filesize];

                client_file_sock.readPOD(buff, filesize);

                out.write(buff, filesize);

                out.flush();
                out.close();

                try {
                    client_file_sock.Close();
                    file_sock.Close();
                } catch (...){
                    cout << "Already closed" << endl;
                }

                delete[] buff;

            } else {
                str_to_nvt(str);
                client.write(str);
            }
        }

        client.Close();
    }

    return 0;
}

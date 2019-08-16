#include <iostream>
#include <sys/select.h>
#include <socket.hpp>
#include <vector>
#include <algorithm>

using namespace std;

using TCPSocket4=Y::Socket<Y::family::ipv4, Y::socktype::stream>;

enum sock_purpose {
    Listen,
    Read,
    Write,
    Err
};

std::pair<TCPSocket4, sock_purpose> p;

template <typename T>
struct Select {

    Select(){
        FD_ZERO(&allset);
        FD_ZERO(&workset);
    }

    void Add(const T& sock){

        socket_pool.push_back(sock);
        FD_SET(sock.fd(), &allset);
        if (sock.fd()>fdmax)
            fdmax=sock.m_sock;
    }

    vector<T*> Ready(){

        workset=allset;

        int ret=select(fdmax+1, &workset, nullptr, nullptr, nullptr);
        if (ret<0)
            throw std::system_error(errno, std::system_category());

        vector<T*> res;
        for (T& x: socket_pool){
            if (FD_ISSET(x.m_sock, &workset)){
                res.push_back(&x);
            }
        }

        return res;
    }

    void Remove(const T& sock){
        socket_pool.erase(std::find_if(socket_pool.begin(), socket_pool.end(), [&sock](T& op){
                              return op.m_sock==sock.m_sock;
        }));

        FD_CLR(sock.m_sock, &allset);
    }

    int fdmax{-1};
    fd_set allset, workset;
    vector<T> socket_pool;
};

int main(void)
{
    Select<TCPSocket4> sel;

    TCPSocket4 sock("0.0.0.0", 9999);

    sock.Bind();
    sock.Listen();

    sel.Add(sock);

    vector<TCPSocket4*> sock_pool;
    string str;
    for (;;){
        sock_pool=sel.Ready();

        if (sock_pool.empty()){
            cout << "socket pool is empty\n";
            this_thread::sleep_for(std::chrono::milliseconds(200));
            this_thread::yield();
        }

        for (auto x: sock_pool){
            if (x->m_sock==sock.m_sock){

                cout << "event on listensock\n";

                sel.Add(sock.Accept());
                continue;
            }

            str=x->readStr("\r\n");

            if (str.empty()){
                x->Shutdown();
                sel.Remove(*x);
                continue;
            }

            cout << "read: " << str << "\n";
            x->writeStr(str);
        }
    }

    return 0;
}

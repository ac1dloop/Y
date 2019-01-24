#ifndef SOCKET_H
#define SOCKET_H

#include <string>
#include <typeinfo>
#include <cstring>
#include <unistd.h>
#include <cstring>
#include <cstdlib>
#include <sys/un.h>
#include <sys/select.h>
#include <fcntl.h>
#include <future>
#include <arpa/inet.h>

#define SOCKDBG

#ifdef SOCKDBG
#include <iostream>
#define PRINT_DBG(VAR) (std::cout<<VAR<<std::endl)
#else
#undef PRINT_DBG
#endif

namespace Util {

using std::string;

string str_to_nvt(const std::string &str){
    return string(str+"\r\n");
}

string nvt_to_str(const std::string &str){
    return str.substr(0, str.size()-2);
}

} //Util namespace

namespace Y {

constexpr int ipv4=AF_INET;
constexpr int ipv6=AF_INET6;

constexpr bool is_address(int a){
    return (a==ipv4||a==ipv6);
}

enum class ErrTypes {
    descriptor,
    timeout,
    socket_option,
    io,
    unknown,
    cant_connect,
    address_format,
};

struct ExceptionInterface {

    ExceptionInterface(){}
    virtual ~ExceptionInterface(){}

    virtual const char* const strErr() const {}

};

typedef ExceptionInterface Err;

template <ErrTypes T>
struct SocketException: ExceptionInterface {

    SocketException(){}

    virtual const char* const strErr() const {
        switch (T) {
        case ErrTypes::address_format:
            return "address_format";
            break;
        case ErrTypes::timeout:
            return "timeout";
            break;
        case ErrTypes::descriptor:
            return "descriptor";
            break;
        case ErrTypes::io:
            return "io";
            break;
        case ErrTypes::socket_option:
            return "invalid socket option";
            break;
        case ErrTypes::cant_connect:
            return "unable to connect";
            break;
        default:
            return "unknown error";
            break;
        }
    }
};

/* fd struct ensures that file descriptor
 * will not be corrupted and in future
 * it may be used avec fcntl syscalls */

struct sockfd{

    sockfd()=default;

    sockfd(const int& i){
        if (i<0)
            throw SocketException<ErrTypes::descriptor>();

        m_fd=i;
    }

    sockfd(const sockfd& op2){
        m_fd=op2.m_fd;
    }

    sockfd& operator=(int i){
        if (i<0)
            throw SocketException<ErrTypes::descriptor>();

        m_fd=i;
        return *this;
    }

    sockfd& operator=(const sockfd& op2){
        m_fd=op2.m_fd;
        return *this;
    }

    sockfd& operator=(sockfd&& op2){
        std::swap(m_fd, op2.m_fd);
        return *this;
    }

    operator int() { return m_fd; }

    int m_fd{-1};
};

template <int T>
struct ip_addr{
};

template <>
struct ip_addr<ipv4>{
    ip_addr(){
            socklen=sizeof(addr4);
    }

    explicit ip_addr(const std::string& address, const uint16_t port){
        int ret;

        ret=inet_pton(ipv4, address.c_str(), &addr4.sin_addr);

        if (ret<=0){
            if (ret==0)
                throw SocketException<ErrTypes::address_format>();

            if (ret<0)
                throw std::system_error(errno, std::generic_category());
        }

        addr4.sin_port=htons(port);
        addr4.sin_family=ipv4;
        socklen=sizeof(addr4);
    }

    ip_addr(const ip_addr& op2){
        addr4=op2.addr4;
        socklen=op2.socklen;
    }

    ip_addr(ip_addr&& op2){
        std::swap(addr4, op2.addr4);
        std::swap(socklen, op2.socklen);
    }

    ip_addr& operator=(const ip_addr& op2){
        addr4=op2.addr4;
        socklen=op2.socklen;

        return *this;
    }

    ip_addr& operator=(ip_addr&& op2){
        std::swap(addr4, op2.addr4);

        return *this;
    }

    std::string Addr() const {
        char tmp[50];

        inet_ntop(ipv4, &addr4.sin_addr, tmp, 50);

        return std::string(tmp);
    }

    void Zero(){
        addr4.sin_addr.s_addr=htonl(INADDR_ANY);
    }

    /* In case it is client address port is ephemeral */

    unsigned Port() const {

        return ntohs(addr4.sin_port);
    }

    sockaddr* operator&() const {
        return (sockaddr*)(&addr4);
    }

    socklen_t socklen;

private:
    sockaddr_in addr4;
};

template <>
struct ip_addr<ipv6>{
    ip_addr(){
            socklen=sizeof(addr6);
    }

    explicit ip_addr(const std::string& address, const uint16_t port){
        int ret;

        ret=inet_pton(ipv6, address.c_str(), &addr6.sin6_addr);

        if (ret<=0){
            if (ret==0)
                throw SocketException<ErrTypes::address_format>();

            if (ret<0)
                throw std::system_error(errno, std::generic_category());
        }

        addr6.sin6_port=htons(port);
        addr6.sin6_family=ipv6;
        socklen=sizeof(addr6);
    }

    ip_addr(const ip_addr& op2){
        addr6=op2.addr6;
        socklen=op2.socklen;
    }

    ip_addr(ip_addr&& op2){
        std::swap(addr6, op2.addr6);
        std::swap(socklen, op2.socklen);
    }

    ip_addr& operator=(const ip_addr& op2){
        addr6=op2.addr6;
        socklen=op2.socklen;

        return *this;
    }

    ip_addr& operator=(ip_addr&& op2){
        std::swap(addr6, op2.addr6);

        return *this;
    }

    std::string Addr() const {
        char tmp[50];

        inet_ntop(ipv6, &addr6.sin6_addr, tmp, 50);

        return std::string(tmp);
    }

    void Zero(){
        addr6.sin6_addr=IN6ADDR_ANY_INIT;
    }

    /* In case it is client address port is ephemeral */

    unsigned Port() const {

        return ntohs(addr6.sin6_port);
    }

    sockaddr* operator&() const {
        return (sockaddr*)(&addr6);
    }

    socklen_t socklen;

private:
    sockaddr_in6 addr6;
};

template<int T>
struct TCPSocket{

    int getSock(){
        return m_sock;
    }

    TCPSocket(){
        m_sock=socket(T, SOCK_STREAM, IPPROTO_TCP);
    }

    TCPSocket(const int& fd){
        m_sock=fd;
    }

    TCPSocket(const std::string& addr, const uint16_t& port):m_addr(addr, port){
        m_sock=socket(T, SOCK_STREAM, IPPROTO_TCP);
    }

    TCPSocket(const TCPSocket& op2){
        m_sock=op2.m_sock;
        m_addr=op2.m_addr;
    }

    TCPSocket(TCPSocket&& op2){
        m_sock=op2.m_sock;
        std::swap(m_addr, op2.m_addr);
    }

    TCPSocket& operator =(const int& fd){
        m_sock=fd;

        return *this;
    }

    TCPSocket& operator=(const TCPSocket& op2){
        m_sock=op2.m_sock;
        m_addr=op2.m_addr;

        return *this;
    }

    TCPSocket& operator=(TCPSocket&& op2){
        std::swap(m_sock, op2.m_sock);
        std::swap(m_addr, op2.m_addr);

        return *this;
    }

    void operator<<(const std::string& op){
        this->write(Util::str_to_nvt(op));
    }

    void operator>>(std::string& op){
        op=Util::nvt_to_str(this->read());
    }

    void setOpt(const int& opt, const int& val=1){
        int ret;
        ret=setsockopt(m_sock, SOL_SOCKET, opt, &val, sizeof(val));
        if (ret<0)
            throw SocketException<ErrTypes::socket_option>();
    }

    void Bind(const std::string& add, const uint16_t& port){
        m_addr=ip_addr<T>(add, port);

        std::cout << "Address " << m_addr.Addr() << ":" << m_addr.Port() << std::endl;

        Bind();
    }

    void Bind(const std::string& add){
        size_t d=add.rfind(':');

        if (d==std::string::npos)
            throw SocketException<ErrTypes::address_format>();

        m_addr=ip_addr<T>(add.substr(0, d),
                          std::stoul(add.substr(d+1, add.size() )));
        Bind();
    }

    void Bind(){
        int ret;
        setOpt(SO_REUSEADDR);
        ret=bind(m_sock, &m_addr, m_addr.socklen);

        if (ret<0)
            throw std::system_error(errno, std::generic_category());
    }

    void Listen(const int& backlog=30){
        int ret;
        ret=listen(m_sock, backlog);

        if (ret<0)
            throw std::system_error(errno, std::generic_category());
    }

    TCPSocket Accept(){
        TCPSocket<T> tmp_sock=accept(m_sock, &tmp_sock.m_addr, &tmp_sock.m_addr.socklen);
        std::cout << "in Accept() " << tmp_sock.Addr() << ":" << tmp_sock.Port()  << " client_fd: " << tmp_sock.getSock() << std::endl;
        return tmp_sock;
    }

    void Connect() {
        int ret;
        ret=connect(m_sock, &m_addr, m_addr.socklen);

        if (ret<0)
            throw std::system_error(errno, std::generic_category());
    }

    void Connect(int timeout=3) const {
        int ret;
        std::future<int> fut=std::async(std::launch::async, connect, m_sock, &m_addr, m_addr.socklen);
        std::future_status status=fut.wait_for(std::chrono::seconds{timeout});
        if (status==std::future_status::timeout)
            throw SocketException<ErrTypes::timeout>();

        ret=fut.get();
        if (ret<0)
            throw SocketException<ErrTypes::cant_connect>();
    }

    void Close(){
        int ret=close(m_sock);

        if (ret<0)
            throw std::system_error(errno, std::generic_category()); //Looks like very bad idea
    }

    std::string read(const std::string& delim="\r\n"){

//        std::cout << "TCPSocket::read()" << std::endl;

        std::string recv_str="";
        int ret=0;
        for (;;){
//            memset(recv_buffer, 0, sizeof(recv_buffer));
            ret=recv(m_sock, recv_buffer, sizeof(recv_buffer), 0);

            if (ret>0)
                recv_str+=std::string(recv_buffer, ret);

            if (ret==0){
                break;
            } else if (recv_str.size()>=delim.size()&&
                       recv_str.substr(recv_str.size()-delim.size(), recv_str.size())==delim){
                break;
            } else if (ret==-1){
                throw std::system_error(errno, std::generic_category());
            }
        }
        return recv_str;
    }

    void write(const std::string& msg){

//        std::cout << "TCPSocket::write()" << std::endl;

        if (!msg.empty()){
            int ret=send(m_sock, msg.c_str(), msg.size(), MSG_NOSIGNAL);
            if (ret==-1){
                throw std::system_error(errno, std::generic_category());
            }
        }
    }

    void writePOD(char* buff, size_t sz){
        int ret=0;
        for (size_t toWrite=sz;toWrite!=0;toWrite-=ret){
            ret=send(m_sock, buff+ret, toWrite, 0);
            if (ret<0)
                throw SocketException<ErrTypes::io>();

        }
    }

    void readPOD(char* buff, size_t sz){
        int ret=0;
        for (size_t toRead=sz;toRead!=0;toRead-=ret){
            ret=recv(m_sock, buff+ret, toRead, 0);
            if (ret==0){
                throw SocketException<ErrTypes::cant_connect>();
            } else if (ret==-1){
                throw SocketException<ErrTypes::io>();
            }
        }
    }

    std::string Addr(){
        return m_addr.Addr();
    }

    uint16_t Port(){
        return m_addr.Port();
    }

protected:
    ip_addr<T> m_addr;
    char recv_buffer[1400];
    sockfd m_sock;
};

template<int T>
struct UDPSocket{

    UDPSocket(){
        m_sock=socket(T, SOCK_DGRAM, IPPROTO_UDP);
    }

    UDPSocket(const std::string& add, const uint16_t& port):m_addr(add, port){
        m_sock=socket(T, SOCK_DGRAM, IPPROTO_UDP);
    }

    UDPSocket(const std::string &add):m_addr(add.substr(0, add.rfind(':')),
                                             std::stoul(add.substr(add.rfind(':')+1, add.size())) ){

        m_sock=socket(T, SOCK_DGRAM, IPPROTO_UDP);
    }

    UDPSocket(const UDPSocket& op2){
        m_sock=op2.m_sock;
        m_addr=op2.m_addr;
    }

    UDPSocket(UDPSocket&& op2){
        m_sock=op2.m_sock;
        std::swap(m_addr, op2.m_addr);
    }

    UDPSocket& operator =(const UDPSocket& op2){
        m_sock=op2.m_sock;
        m_addr=op2.m_addr;

        return *this;
    }

    UDPSocket& operator =(UDPSocket&& op2){
        std::swap(m_sock, op2.m_sock);
        std::swap(m_addr, op2.m_addr);

        return *this;
    }

    void BindAny(){
        int ret;
        setOpt(SO_REUSEADDR);

        m_addr.Zero();
        ret=bind(m_sock, &m_addr, m_addr.socklen);

        if (ret<0)
            throw std::system_error(errno, std::generic_category());
    }

    void Bind(){
        int ret;
        setOpt(SO_REUSEADDR);
        ret=bind(m_sock, &m_addr, m_addr.socklen);

        if (ret<0)
            throw std::system_error(errno, std::generic_category());
    }

    void Bind(const std::string& add){
        size_t d=add.rfind(':');
        int ret;

        if (d==std::string::npos)
            throw SocketException<ErrTypes::address_format>();

        m_addr=ip_addr<T>(add.substr(0, d), add.substr(d+1, add.size()));

        setOpt(SO_REUSEADDR);

        ret=bind(m_sock, &m_addr, m_addr.socklen);

        if (ret<0)
            throw std::system_error(errno, std::generic_category());
    }

    void Bind(const std::string &add, const uint16_t& port){
        int ret;
        m_addr=ip_addr<T>(add, port);

        setOpt(SO_REUSEADDR);

        ret=bind(m_sock, &m_addr, m_addr.socklen);

        if (ret<0)
            throw std::system_error(errno, std::generic_category());
    }

    void setOpt(const int& opt, const int& val=1){
        int ret;
        ret=setsockopt(m_sock, SOL_SOCKET, opt, &val, sizeof(val));

        if (ret<0)
            throw SocketException<ErrTypes::socket_option>();
    }

    void send(const std::string& msg, ip_addr<T>& target){
        if (!msg.empty()){
            int ret=sendto(m_sock, msg.c_str(), msg.size(), 0, &target, target.socklen);
            if (ret==-1){
                throw std::system_error(errno, std::generic_category());
            }
        }
    }

    void send(const std::string& msg){
        if (!msg.empty()){
            int ret=sendto(m_sock, msg.c_str(), msg.size(), 0, &m_addr, m_addr.socklen);
            if (ret==-1){
                throw std::system_error(errno, std::generic_category());
            }
        }
    }

    std::pair<std::string, ip_addr<T>> receiveonce(){
        std::string recv_str="";
        ip_addr<T> client;
        int ret=0;
        memset(recv_buffer, 0, sizeof(recv_buffer));
        ret=recvfrom(m_sock, recv_buffer, sizeof(recv_buffer), 0, &client, &client.socklen);
        recv_str.append(recv_buffer);

        if (ret<0)
            throw std::system_error(errno, std::generic_category());

        return std::make_pair(recv_str, client);
    }

    std::pair<std::string, ip_addr<T>> receive(const std::string& delim="\r\n"){
        std::string recv_str="";
        ip_addr<T> client;
        int ret=0;
        for (;;){
            memset(recv_buffer, 0, sizeof(recv_buffer)); // <<--- ???????????
            ret=recvfrom(m_sock, recv_buffer, sizeof(recv_buffer), 0, &client, &client.socklen);
            recv_str.append(recv_buffer);
            if (ret==0){
                break;
            } else if (recv_str.size()>=delim.size()&&
                       recv_str.substr(recv_str.size()-delim.size(), recv_str.size())==delim){
                break;
            } else if (ret==-1){
                throw std::system_error(errno, std::generic_category());
            }
        }
        return std::make_pair(recv_str, client);
    }

    void sendPOD(void* buff, const size_t& sz){
        size_t toWrite=sz;
        int ret=0;
        for (;toWrite!=0;){
            ret=sendto(m_sock, buff+ret, toWrite, 0, &m_addr, m_addr.socklen);
            if (ret==-1){
                throw std::system_error(errno,std::generic_category());
            }
            toWrite-=ret;
        }
    }

    void sendPOD(void* buff, const size_t& sz, const ip_addr<T>& target){
        size_t toWrite=sz;
        int ret=0;
        for (;toWrite!=0;){
            ret=sendto(m_sock, buff+ret, toWrite, 0, &target, target.socklen);
            if (ret==-1){
                throw std::system_error(errno,std::generic_category());
            }
            toWrite-=ret;
        }
    }

    ip_addr<T> recvPOD(void* buff, const size_t& sz){
        size_t toRead=sz;
        ip_addr<T> client;
        int ret=0;
        for (;toRead!=0;){
            ret=recvfrom(m_sock, buff+ret, toRead, 0, &client, &client.socklen);
            if (ret==0){
                break;
            } else if (ret==-1){
                throw std::system_error(errno,std::generic_category());
            }
            toRead-=ret;
        }

        return client;
    }

    void Close(){
        int ret=close(m_sock);
        if (ret<0)
            throw std::system_error(errno, std::generic_category());
    }

    std::string Addr(){
        return m_addr.Addr();
    }

    uint16_t Port(){
        return m_addr.Port();
    }


protected:
    ip_addr<T> m_addr;
    char recv_buffer[1400];
    sockfd m_sock;
};

typedef std::pair<std::string, ip_addr<ipv4>> msg_host4;
typedef std::pair<std::string, ip_addr<ipv6>> msg_host6;

} //Y namespace

#endif // SOCKET_H

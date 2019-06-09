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
#include <netdb.h>

#include <iostream>

#define MAX_BUF_LINE 256

namespace Y {

/**
 * @brief The family enum
 * Supported socket families
 */
enum family {
    ipv4 = AF_INET,
    ipv6 = AF_INET6,
    local = AF_LOCAL, ///unix socket
    route = AF_ROUTE, ///routing socket
    key = AF_KEY ///encryption
};

/**
 * @brief The socktype enum
 * Supported socket types
 */
enum socktype {
    stream = SOCK_STREAM, ///TCP
    datagram = SOCK_DGRAM, ///UDP
    seqpacket = SOCK_SEQPACKET,
    raw = SOCK_RAW ///RAW
};

/**
 * @brief The ipproto enum
 * Only applicable when family is ipv4 or ipv6 is used
 */
enum ipproto {
    tcp = IPPROTO_TCP,
    udp = IPPROTO_UDP,
    sctp = IPPROTO_SCTP
};

/**
 * @brief The shut enum
 * Three types of shutting socket down
 */
enum shut {
    read=SHUT_RD,
    write=SHUT_WR,
    rw=SHUT_RDWR
};

/**
 * @brief The opt_socket enum
 * Socket level options for sockets
 */
enum opt_socket {
    level=SOL_SOCKET,
    broadcast=SO_BROADCAST,
    debug=SO_DEBUG,
    dontroute=SO_DONTROUTE,
    error=SO_ERROR,
    keepalive=SO_KEEPALIVE,
    linger=SO_LINGER,
    oobinline=SO_OOBINLINE,
    receive_buff=SO_RCVBUF,
    send_buff=SO_SNDBUF,
    receive_low_watermark=SO_RCVLOWAT,
    send_low_watermark=SO_SNDLOWAT,
    receive_timeout=SO_RCVTIMEO,
    send_timeout=SO_SNDTIMEO,
    reuseaddr=SO_REUSEADDR,
    reuseport=SO_REUSEPORT,
    type=SO_TYPE,
#ifdef SO_USELOOPBACK
    loopback=SO_USELOOPBACK
#endif
};

/**
 * @brief The opt_ip enum
 * IP level options for sockets
 */
enum opt_ip {
    include_header=IP_HDRINCL,
    header_opts=IP_OPTIONS,
    dest_ip_addr=IP_RECVORIGDSTADDR,
    type_of_service=IP_TOS,
    TTL=IP_TTL,
    multicast_if=IP_MULTICAST_IF,
    multicast_TTL=IP_MULTICAST_TTL,
    multicast_loopback=IP_MULTICAST_LOOP,
};

enum opt_ip6 {
    checksum=IPV6_CHECKSUM,
#ifdef IPV6_DONTFRAG
    drop_large_packets=IPV6_DONTFRAG,
#endif
    next_hop=IPV6_NEXTHOP,
    mtu_path=IPV6_MTU,
};

//enum opt_tcp {
//    max_segment=TCP_MAXSEG,
//    nodelay=TCP_NODELAY
//};

enum class errtypes {
    descriptor,
    timeout,
};

struct SocketException: public std::exception {

    explicit SocketException(errtypes err):t(err){}

    virtual ~SocketException() throw() {}

    virtual const char* what() const throw() {
        switch (t) {
        case errtypes::descriptor:
            return "Not valid file descriptor";
        default:
            return "Unknown";
        }
    }

private:
    errtypes t;
};

/**
 * @brief The sockfd struct
 * struct ensures that file descriptor not corrupted
 */
struct sockfd {

    sockfd()=default;

    sockfd(const int& i){
        if (i<0)
            throw SocketException(errtypes::descriptor);

        m_fd=i;
    }

    sockfd(const sockfd& op2){
        m_fd=op2.m_fd;
    }

    sockfd& operator=(int i){
        if (i<0)
            throw SocketException(errtypes::descriptor);

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

    operator int() const { return m_fd; }

private:
    int m_fd{-1};
};

template <family T>
struct ip_addr{
};

template <>
struct ip_addr<family::ipv4>{
    ip_addr():socklen(sizeof(m_addr)) {}

    explicit ip_addr(const char* addr, uint16_t port){
        int ret;

        ret=inet_pton(family::ipv4, addr, &m_addr.sin_addr);

        if (ret==0)
            throw std::logic_error("Incorrect address format");

        if (ret<0)
            throw std::system_error(errno, std::system_category());

        m_addr.sin_port=htons(port);
        m_addr.sin_family=family::ipv4;
    }

    ip_addr(uint16_t port){
        m_addr.sin_port=htons(port);
        m_addr.sin_family=family::ipv4;
        m_addr.sin_addr.s_addr=htonl(INADDR_ANY);
    }

    ip_addr(const ip_addr& op2):socklen(op2.socklen),
                                m_addr(op2.m_addr) {}

    ip_addr(ip_addr&& op2){
        std::swap(m_addr, op2.m_addr);
        std::swap(socklen, op2.socklen);
    }

    ip_addr& operator=(const ip_addr& op2){
        m_addr=op2.m_addr;
        socklen=op2.socklen;

        return *this;
    }

    ip_addr& operator=(ip_addr&& op2){
        std::swap(m_addr, op2.m_addr);

        return *this;
    }

    std::string Addr() const {
        char tmp[INET_ADDRSTRLEN];

        inet_ntop(family::ipv4, &m_addr.sin_addr, tmp, INET_ADDRSTRLEN);

        return std::string(tmp, strlen(tmp));
    }

    unsigned Port() const { return ntohs(m_addr.sin_port); }

    sockaddr* operator&() { return reinterpret_cast<sockaddr*>(&m_addr); }

    socklen_t socklen{sizeof(m_addr)};
private:
    sockaddr_in m_addr;
};

template <>
struct ip_addr<family::ipv6>{
    ip_addr():socklen(sizeof(m_addr)) { }

    explicit ip_addr(const char* addr, uint16_t port){
        int ret;

        ret=inet_pton(family::ipv6, addr, &m_addr.sin6_addr);

        if (ret==0)
            throw std::logic_error("Incorrect address format");

        if (ret<0)
            throw std::system_error(errno, std::system_category());

        m_addr.sin6_port=htons(port);
        m_addr.sin6_family=family::ipv6;
    }

    ip_addr(uint16_t port) {
        m_addr.sin6_port=htons(port);
        m_addr.sin6_family=family::ipv6;
        int ret=inet_pton(family::ipv6, "::", &m_addr.sin6_addr);

        if (ret<0)
            throw std::system_error(errno, std::system_category());
    }

    ip_addr(const ip_addr& op2):socklen(op2.socklen),
                                m_addr(op2.m_addr) {}

    ip_addr(ip_addr&& op2){
        std::swap(m_addr, op2.m_addr);
        std::swap(socklen, op2.socklen);
    }

    ip_addr& operator=(const ip_addr& op2){
        m_addr=op2.m_addr;
        socklen=op2.socklen;

        return *this;
    }

    ip_addr& operator=(ip_addr&& op2){
        std::swap(m_addr, op2.m_addr);
        std::swap(socklen, op2.socklen); //may be unnecessary

        return *this;
    }

    std::string Addr() const {
        char tmp[INET6_ADDRSTRLEN];

        inet_ntop(family::ipv6, &m_addr.sin6_addr, tmp, INET6_ADDRSTRLEN);

        return std::string(tmp, strlen(tmp));
    }

    unsigned Port() const { return ntohs(m_addr.sin6_port); }

    sockaddr* operator&() { return reinterpret_cast<sockaddr*>(&m_addr); }

    socklen_t socklen{sizeof(m_addr)};
private:
    sockaddr_in6 m_addr;
};

template <family f, socktype t>
struct Socket {
};

template <family f>
struct Socket<f, socktype::stream> {

    explicit Socket(){}

    Socket(const char* addr, const uint16_t port):
        m_sock(socket(f, socktype::stream, ipproto::tcp)),
        m_addr(std::move(ip_addr<f>(addr, port)))
    {}

    Socket(const Socket& op2):
        m_sock(op2.m_sock),
        m_addr(op2.m_addr)
    {}

    Socket(Socket&& op2):
        m_sock(std::move(op2.m_sock)),
        m_addr(std::move(op2.m_addr))
    {}

    Socket& operator=(const Socket& op2){
        this->m_sock=op2.m_sock;
        this->m_addr=op2.m_addr;

        return *this;
    }

    Socket& operator=(Socket&& op2){
        this->m_sock=sockfd(std::move(op2.m_sock));
        this->m_addr=ip_addr<f>(std::move(op2.m_addr));

        return *this;
    }

    void Bind(){
        int val=1;

        int ret=setsockopt(m_sock, opt_socket::level, opt_socket::reuseaddr, &val, sizeof(val));

        if (ret==0)
            ret=bind(m_sock, &m_addr, m_addr.socklen);


        if (ret<0)
            throw std::system_error(errno, std::system_category());
    }

    void Listen(const int queue=30){
        int ret=listen(m_sock, queue);
        if (ret<0)
            throw std::system_error(errno, std::system_category());
    }

    Socket Accept(){
        Socket<f, socktype::stream> client;

        for (int ret=0;;ret=accept(m_sock, &client.m_addr, &client.m_addr.socklen)){
            if (ret<0&&errno==ECONNABORTED)
                continue;

            if (ret<0)
                throw std::system_error(errno, std::system_category());

            if (ret>0){
                client.m_sock=ret;
                break;
            }
        }

        return client;
    }

    void Connect(){
        int ret=connect(m_sock, &m_addr, m_addr.socklen);

        if (ret<0)
            throw std::system_error(errno, std::system_category());
    }

    void Connect(std::chrono::milliseconds d=std::chrono::milliseconds(3000)){
        int ret;
        std::future<int> fut=std::async(std::launch::async, connect, m_sock, &m_addr, m_addr.socklen);
        std::future_status status=fut.wait_for(d);
        if (status==std::future_status::timeout)
            throw SocketException(errtypes::timeout);

        ret=fut.get();
        if (ret<0)
            throw std::system_error(errno, std::system_category());
    }

    /**
     * @brief readStr
     * @param delim
     * @return string including delimeter character
     * Extremely slow implementation. Use only for fun.
     */
    std::string readStr(const char delim='\n'){
        ssize_t ret=0;

        std::string res="";
        char buf{0};
        for (;;){

            ret=recv(m_sock, &buf, 1, 0);

            if (ret==-1){
                state=false;
                throw std::system_error(errno, std::system_category());
            }

            /* Connection closed??? */
            if (ret==0){
                state=false;
                break;
            }

            res+=buf;
            if (buf==delim)
                break;
        }

        return res;
    }

    /**
     * @brief readStr
     * @param delim
     * @return string including delimeter
     * Nice for trivial text protocols like telnet.
     */
    std::string readStr(const std::string delim="\r\n"){
        ssize_t ret=0;
        std::string res="";
        char buf[MAX_BUF_LINE]{0};
        for (;;){

            /* just take a look at the data */
            ret=recv(m_sock, buf, MAX_BUF_LINE, MSG_PEEK);

            /* system error for sure */
            if (ret<0){
                state=false;
                throw std::system_error(errno, std::system_category());
            }

            /* Connection closed??? */
            if (ret==0){
                state=false;
                break;
            }

            /* tmp string that has been read */
            std::string tmp(buf, ret);

    //        cout << "tmp: " << tmp << " ret: " << ret << "\n";

            /* check if contains delim */
            size_t d=tmp.find(delim);

            /* delim is not found yet */
            if (d==std::string::npos){

    //            cout << "no delim found\n";

                /* append new data to result */
                res+=tmp;

                /* remove data from socket */
                recv(m_sock, buf, ret, 0);
                continue;
            } else {

    //            cout << "delim found\n";

                /* append new data with delim to result */
                res+=tmp.substr(0, d+delim.size());

                /* remove data before delim and delim */
                recv(m_sock, buf, d+delim.size(), 0);

                break;
            }
        }

        return res;
    }

    void writeStr(const std::string& msg){
        ssize_t ret=0;
        size_t pos=0;
        size_t toWrite=msg.size();
        for (;toWrite!=0;){

            ret=send(m_sock, msg.data()+pos, toWrite, 0);

            if (ret<0){
                state=false;
                throw std::system_error(errno, std::system_category());
            }

            pos+=static_cast<size_t>(ret);
            toWrite-=static_cast<size_t>(ret);
        }
    }

    void Shutdown(shut how=shut::rw)
    {
        int ret=shutdown(m_sock, how);

        if (ret==ENOTCONN)
            return;
        else if (ret<0)
            throw std::system_error(errno, std::system_category());
    }

    /**
     * @brief TCPSocket4::Close
     * Gently close socket. Try to use linger struct to send all data before clearing buffers.
     */
    void Close(int sec=10)
    {
        struct linger ling;
        ling.l_onoff=1;
        ling.l_linger=sec;

        int ret=setsockopt(m_sock, opt_socket::level, opt_socket::linger, &ling, sizeof(ling));
        /* probably no reason to handle this error */
    //    if (ret<0)
    //        throw std::system_error(errno, std::system_category());

        ret=close(m_sock);
        if (ret<0){
            /* linger timed out */
            if (ret==EWOULDBLOCK)
                return;

            throw std::system_error(errno, std::system_category());
        }
    }

    std::string Addr() const {
        return m_addr.Addr();
    }

    uint16_t Port() const {
        return m_addr.Port();
    }

    bool state;

//private:
    sockfd m_sock;
    ip_addr<f> m_addr;
};

//template<int T>
//struct TCPSocket{

//    TCPSocket():m_sock(socket(T, SOCK_STREAM, IPPROTO_TCP)) {}

//    TCPSocket(int fd):m_sock(fd) {}

//    TCPSocket(const std::string& addr, const uint16_t& port):m_addr(addr.c_str(), port),
//                                                             m_sock(socket(T, SOCK_STREAM, IPPROTO_TCP)) {}

//    TCPSocket(const TCPSocket& op2):m_sock(op2.m_sock),
//                                    m_addr(op2.m_addr) {}

//    TCPSocket(TCPSocket&& op2){
//        m_sock=op2.m_sock;
//        std::swap(m_addr, op2.m_addr);
//    }

//    TCPSocket& operator =(int fd){
//        m_sock=fd;

//        return *this;
//    }

//    TCPSocket& operator=(const TCPSocket& op2){
//        m_sock=op2.m_sock;
//        m_addr=op2.m_addr;

//        return *this;
//    }

//    TCPSocket& operator=(TCPSocket&& op2){
//        std::swap(m_sock, op2.m_sock);
//        std::swap(m_addr, op2.m_addr);

//        return *this;
//    }

//    void Listen(const int& backlog=30){
//        int ret;
//        ret=listen(m_sock, backlog);

//        if (ret<0)
//            throw std::system_error(errno, std::generic_category());
//    }

//    TCPSocket Accept(){
//        TCPSocket<T> tmp_sock=accept(m_sock, &tmp_sock.m_addr, &tmp_sock.m_addr.socklen);
//        return tmp_sock;
//    }

//    void Connect() {
//        int ret;
//        ret=connect(m_sock, &m_addr, m_addr.socklen);

//        if (ret<0)
//            throw std::system_error(errno, std::generic_category());
//    }

//    void Connect(int timeout=3) const {
//        int ret;
//        std::future<int> fut=std::async(std::launch::async, connect, m_sock, &m_addr, m_addr.socklen);
//        std::future_status status=fut.wait_for(std::chrono::seconds{timeout});
//        if (status==std::future_status::timeout)
//            throw SocketException<ErrTypes::timeout>();

//        ret=fut.get();
//        if (ret<0)
//            throw SocketException<ErrTypes::cant_connect>();
//    }

//    void Close(){
//        int ret=close(m_sock);

//        if (ret<0)
//            throw std::system_error(errno, std::generic_category()); //Looks like very bad idea
//    }

//    std::string read(const std::string& delim="\r\n"){

//        std::string recv_str="";
//        int ret=0;
//        for (;;){
//            ret=recv(m_sock, recv_buffer, sizeof(recv_buffer), 0);

//            if (ret>0)
//                recv_str+=std::string(recv_buffer, ret);

//            if (ret==0){
//                throw SocketException<ErrTypes::connection_closed>();
//                break;
//            } else if (recv_str.size()>=delim.size()&&
//                       recv_str.substr(recv_str.size()-delim.size(), recv_str.size())==delim){
//                break;
//            } else if (ret==-1){
//                throw std::system_error(errno, std::generic_category());
//            }
//        }
//        return recv_str;
//    }

//    void write(const std::string& msg){

//        if (!msg.empty()){
//            int ret=send(m_sock, msg.c_str(), msg.size(), MSG_NOSIGNAL);
//            if (ret==-1){
//                throw SocketException<ErrTypes::io>();
//            }
//        }
//    }

//    void writePOD(char* buff, size_t sz){
//        int ret=0;
//        for (size_t toWrite=sz;toWrite!=0;toWrite-=ret){
//            ret=send(m_sock, buff+ret, toWrite, 0);
//            if (ret<0)
//                throw SocketException<ErrTypes::io>();

//        }
//    }

//    void readPOD(char* buff, size_t sz){
//        int ret=0;
//        for (size_t toRead=sz;toRead!=0;toRead-=ret){
//            ret=recv(m_sock, buff+ret, toRead, 0);
//            if (ret==0){
//                throw SocketException<ErrTypes::connection_closed>();
//            } else if (ret==-1){
//                throw SocketException<ErrTypes::io>();
//            }
//        }
//    }

//    std::string Addr() const {
//        return m_addr.Addr();
//    }

//    uint16_t Port() const {
//        return m_addr.Port();
//    }

//protected:
//    ip_addr<T> m_addr;
//    sockfd m_sock;
//};

//template<int T>
//struct UDPSocket{

//    UDPSocket():m_sock(socket(T, SOCK_DGRAM, IPPROTO_UDP)) {}

//    UDPSocket(const std::string& add, const uint16_t& port):m_addr(add, port), m_sock(socket(T, SOCK_DGRAM, IPPROTO_UDP)) {}

//    UDPSocket(const std::string &add):m_addr(add.substr(0, add.rfind(':')),
//                                             std::stoul(add.substr(add.rfind(':')+1, add.size())) ), m_sock(socket(T, SOCK_DGRAM, IPPROTO_UDP)) {}

//    UDPSocket(const UDPSocket& op2):m_sock(op2.m_sock),
//                                    m_addr(op2.m_addr) {}

//    UDPSocket(UDPSocket&& op2){
//        m_sock=op2.m_sock;
//        std::swap(m_addr, op2.m_addr);
//    }

//    UDPSocket& operator =(const UDPSocket& op2){
//        m_sock=op2.m_sock;
//        m_addr=op2.m_addr;

//        return *this;
//    }

//    UDPSocket& operator =(UDPSocket&& op2){
//        std::swap(m_sock, op2.m_sock);
//        std::swap(m_addr, op2.m_addr);

//        return *this;
//    }

//    void BindAny(){
//        int ret;
//        setOpt(SO_REUSEADDR);

//        m_addr.toAnyAddr();
//        ret=bind(m_sock, &m_addr, m_addr.socklen);

//        if (ret<0)
//            throw std::system_error(errno, std::generic_category());
//    }

//    void Bind(){
//        int ret;
//        setOpt(SO_REUSEADDR);
//        ret=bind(m_sock, &m_addr, m_addr.socklen);

//        if (ret<0)
//            throw std::system_error(errno, std::generic_category());
//    }

//    void Bind(const std::string& add){
//        size_t d=add.rfind(':');
//        int ret;

//        if (d==std::string::npos)
//            throw SocketException<ErrTypes::address_format>();

//        m_addr=ip_addr<T>(add.substr(0, d), add.substr(d+1, add.size()));

//        setOpt(SO_REUSEADDR);

//        ret=bind(m_sock, &m_addr, m_addr.socklen);

//        if (ret<0)
//            throw std::system_error(errno, std::generic_category());
//    }

//    void Bind(const std::string &add, const uint16_t& port){
//        int ret;
//        m_addr=ip_addr<T>(add, port);

//        setOpt(SO_REUSEADDR);

//        ret=bind(m_sock, &m_addr, m_addr.socklen);

//        if (ret<0)
//            throw std::system_error(errno, std::generic_category());
//    }

//    void setOpt(const int& opt, const int& val=1){
//        int ret;
//        ret=setsockopt(m_sock, SOL_SOCKET, opt, &val, sizeof(val));

//        if (ret<0)
//            throw SocketException<ErrTypes::socket_option>();
//    }

//    void send(const std::string& msg, ip_addr<T>& target){
//        if (!msg.empty()){
//            int ret=sendto(m_sock, msg.c_str(), msg.size(), 0, &target, target.socklen);
//            if (ret<0){
//                throw SocketException<ErrTypes::io>();
//            }
//        }
//    }

//    void send(const std::string& msg){
//        if (!msg.empty()){
//            int ret=sendto(m_sock, msg.c_str(), msg.size(), 0, &m_addr, m_addr.socklen);
//            if (ret<0){
//                throw SocketException<ErrTypes::io>();
//            }
//        }
//    }

//    std::pair<std::string, ip_addr<T>> receiveonce(){
//        std::string recv_str="";
//        ip_addr<T> client;
//        int ret=0;
//        memset(recv_buffer, 0, sizeof(recv_buffer));
//        ret=recvfrom(m_sock, recv_buffer, sizeof(recv_buffer), 0, &client, &client.socklen);
//        recv_str.append(recv_buffer);

//        if (ret<0)
//            throw SocketException<ErrTypes::io>();

//        return std::make_pair(recv_str, client);
//    }

//    std::pair<std::string, ip_addr<T>> receive(const std::string& delim="\r\n"){
//        std::string recv_str="";
//        ip_addr<T> client;
//        int ret=0;
//        for (;;){
//            ret=recvfrom(m_sock, recv_buffer, sizeof(recv_buffer), 0, &client, &client.socklen);
//            recv_str+=std::string(recv_buffer, ret);
//            if (ret==0){
//                break;
//            } else if (recv_str.size()>=delim.size()&&
//                       recv_str.substr(recv_str.size()-delim.size(), recv_str.size())==delim){
//                break;
//            } else if (ret==-1){
//                throw SocketException<ErrTypes::io>();
//            }
//        }
//        return std::make_pair(recv_str, client);
//    }

//    void sendPOD(void* buff, const size_t& sz){
//        size_t toWrite=sz;
//        int ret=0;
//        for (;toWrite!=0;){
//            ret=sendto(m_sock, buff+ret, toWrite, 0, &m_addr, m_addr.socklen);
//            if (ret<0){
//                throw SocketException<ErrTypes::io>();
//            }
//            toWrite-=ret;
//        }
//    }

//    void sendPOD(void* buff, const size_t& sz, const ip_addr<T>& target){
//        size_t toWrite=sz;
//        int ret=0;
//        for (;toWrite!=0;){
//            ret=sendto(m_sock, buff+ret, toWrite, 0, &target, target.socklen);
//            if (ret<0){
//                throw SocketException<ErrTypes::io>();
//            }
//            toWrite-=ret;
//        }
//    }

//    ip_addr<T> recvPOD(void* buff, const size_t& sz){
//        size_t toRead=sz;
//        ip_addr<T> client;
//        int ret=0;
//        for (;toRead!=0;){
//            ret=recvfrom(m_sock, buff+ret, toRead, 0, &client, &client.socklen);
//            if (ret==0){
//                break;
//            } else if (ret<0){
//                throw SocketException<ErrTypes::io>();
//            }
//            toRead-=ret;
//        }

//        return client;
//    }

//    void Close(){
//        int ret=close(m_sock);

//        if (ret<0)
//            throw std::system_error(errno, std::generic_category());
//    }

//    std::string Addr() const {
//        return m_addr.Addr();
//    }

//    uint16_t Port() const {
//        return m_addr.Port();
//    }


//protected:
//    ip_addr<T> m_addr;
//    char recv_buffer[1400];
//    sockfd m_sock;
//};

typedef std::pair<std::string, ip_addr<ipv4>> msg_host4;
typedef std::pair<std::string, ip_addr<ipv6>> msg_host6;

} //Y namespace

#endif // SOCKET_H

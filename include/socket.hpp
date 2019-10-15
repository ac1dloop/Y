#ifndef SOCKET_H
#define SOCKET_H

/* for Socket struct */
#include <arpa/inet.h>
#include <unistd.h> //close()
#include <string>
#include <future> //connect with timeout
#include <sys/un.h> //local socket

#include <typeinfo>
#include <cstring> //strlen, memset
#include <netdb.h>
#include <cstring>

#include <vector>

#include <iostream>

/* TO DO
 * raw sockets (probably packet class)
 * provide as library
 * move definitions to .cpp file
 * add win support
 * nothrow #ifdef
 * inherit from std::stream
 * add resolve functions */

#define MAX_BUF_LINE 256 
#define UDP_MAX_BUF 1500

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
#ifdef SOL_SOCKET
    level=SOL_SOCKET,
#endif
#ifdef SO_BROADCAST
    broadcast=SO_BROADCAST,
#endif
#ifdef SO_DEBUG
    debug=SO_DEBUG,
#endif
#ifdef SO_DONTROUTE
    dontroute=SO_DONTROUTE,
#endif
#ifdef SO_ERROR
    error=SO_ERROR,
#endif
#ifdef SO_KEEPALIVE
    keepalive=SO_KEEPALIVE,
#endif
#ifdef SO_LINGER
    linger=SO_LINGER,
#endif
#ifdef SO_OOBINLINE
    oobinline=SO_OOBINLINE,
#endif
#ifdef SO_RCVBUF
    receive_buff=SO_RCVBUF,
#endif
#ifdef SO_SNDBUF
    send_buff=SO_SNDBUF,
#endif
#ifdef SO_RCVLOWAT
    receive_low_watermark=SO_RCVLOWAT,
#endif
#ifdef SO_SNDLOWAT
    send_low_watermark=SO_SNDLOWAT,
#endif
#ifdef SO_RCVTIMEO
    receive_timeout=SO_RCVTIMEO,
#endif
#ifdef SO_SNDTIMEO
    send_timeout=SO_SNDTIMEO,
#endif
#ifdef SO_REUSEADDR
    reuseaddr=SO_REUSEADDR,
#endif
#ifdef SO_REUSEPORT
    reuseport=SO_REUSEPORT,
#endif
#ifdef SO_TYPE
    type=SO_TYPE,
#endif
#ifdef SO_USELOOPBACK
    loopback=SO_USELOOPBACK
#endif
};

/**
 * @brief The opt_ip enum
 * IP level options for sockets
 */
enum opt_ip {
#ifdef IP_HDRINCL
    include_header=IP_HDRINCL,
#endif
#ifdef IP_OPTIONS
    header_opts=IP_OPTIONS,
#endif
#ifdef IP_RECVORIGDSTADDR
    dest_ip_addr=IP_RECVORIGDSTADDR,
#endif
#ifdef IP_TOS
    type_of_service=IP_TOS,
#endif
#ifdef IP_TTL
    TTL=IP_TTL,
#endif
#ifdef IP_MULTICAST_IF
    multicast_if=IP_MULTICAST_IF,
#endif
#ifdef IP_MULTICAST_TTL
    multicast_TTL=IP_MULTICAST_TTL,
#endif
#ifdef IP_MULTICAST_LOOP
    multicast_loopback=IP_MULTICAST_LOOP,
#endif
};

enum opt_ip6 {
#ifdef IPV6_CHECKSUM
    checksum=IPV6_CHECKSUM,
#endif
#ifdef IPV6_DONTFRAG
    drop_large_packets=IPV6_DONTFRAG,
#endif
#ifdef IPV6_NEXTHOP
    next_hop=IPV6_NEXTHOP,
#endif
#ifdef IPV6_MTU
    mtu_path=IPV6_MTU,
#endif
};

enum class errtypes {
    descriptor,
    timeout,
};

static std::vector<std::string> getAddrByName(const std::string& hostname, socktype t, const std::string& service_or_port){
    std::vector<std::string> res;

    addrinfo hints, *result;
    addrinfo *it;

    memset(&hints, 0, sizeof(hints));

    hints.ai_family=AF_UNSPEC;
    hints.ai_socktype=t;
    hints.ai_flags=AI_CANONNAME;

    int ret=getaddrinfo(hostname.c_str(), service_or_port.c_str(), &hints, &result);
    if (ret!=0){
        throw std::logic_error(gai_strerror(ret));
    }

    for (it=result;it!=nullptr;it=it->ai_next){
        char tmp[INET6_ADDRSTRLEN];

        if (it->ai_family==AF_INET){
            inet_ntop(it->ai_family, &reinterpret_cast<sockaddr_in*>(it->ai_addr)->sin_addr, tmp, INET6_ADDRSTRLEN);
        } else {
            inet_ntop(it->ai_family, &reinterpret_cast<sockaddr_in6*>(it->ai_addr)->sin6_addr, tmp, INET6_ADDRSTRLEN);
        }

        res.push_back(tmp);
    }

    freeaddrinfo(result);

    return res;
}

static std::vector<std::string> getNameByAddr(const std::string& addr, socktype t, const unsigned short& port){
    std::vector<std::string> res;

    addrinfo hints, *result;
    addrinfo *it;

    memset(&hints, 0, sizeof(hints));

    hints.ai_family=AF_UNSPEC;
    hints.ai_socktype=t;
    hints.ai_flags=AI_CANONNAME;

    int ret=getaddrinfo(addr.c_str(), nullptr, nullptr, &result);
    if (ret!=0){
        throw std::logic_error(gai_strerror(ret));
    }

    for (it=result;it!=nullptr;it=it->ai_next){
        char host[512];
        ret=getnameinfo(it->ai_addr, it->ai_addrlen, host, 512, nullptr, 0, 0);

        res.emplace_back(host);
    }

    freeaddrinfo(result);

    return res;
}

struct SocketException: public std::exception {

    explicit SocketException(errtypes err):t(err){}

    virtual ~SocketException() throw() {}

    virtual const char* what() const throw() {
        switch (t) {
        case errtypes::descriptor:
            return "Invalid file descriptor";
        case errtypes::timeout:
            return "Timeout";
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

using std::cout;

template <>
struct ip_addr<family::local>{

    ip_addr():socklen(sizeof(m_addr)) {}

    ip_addr(const char* path):socklen(sizeof(m_addr)){
        m_addr.sun_family=family::local;

        if (strlen(path)>sizeof(m_addr.sun_path))
            throw std::logic_error("Too big pathname for local socket");

        strncpy(m_addr.sun_path, path, sizeof(m_addr.sun_path)-1);
    }

    ip_addr(const ip_addr& op2){
        socklen=op2.socklen;
        strcpy(m_addr.sun_path, op2.m_addr.sun_path);
        m_addr.sun_family=op2.m_addr.sun_family;
    }

    ip_addr(ip_addr&& op2):
        socklen(std::move(op2.socklen))
    {
        std::swap(m_addr.sun_path, op2.m_addr.sun_path);
        std::swap(m_addr.sun_family, op2.m_addr.sun_family);
    }

    ip_addr& operator=(const ip_addr& op2){
        socklen=op2.socklen;
        strcpy(m_addr.sun_path, op2.m_addr.sun_path);
        m_addr.sun_family=op2.m_addr.sun_family;

        return *this;
    }

    ip_addr& operator=(ip_addr&& op2) {
        std::swap(socklen, op2.socklen);
        std::swap(m_addr.sun_path, op2.m_addr.sun_path);
        std::swap(m_addr.sun_family, op2.m_addr.sun_family);

        return *this;
    }

    std::string Path(){
        return std::string(m_addr.sun_path, strlen(m_addr.sun_path));
    }

    sockaddr* operator&() { return reinterpret_cast<sockaddr*>(&m_addr); }

    socklen_t socklen;
private:
    sockaddr_un m_addr;
};

template <>
struct ip_addr<family::ipv4>{
    ip_addr():socklen(sizeof(m_addr)) {}

    ip_addr(const sockaddr_in addr):m_addr(addr), socklen(sizeof(addr)){}

    ip_addr(const char* addr, uint16_t port){
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

    ip_addr(const sockaddr_in6& addr):m_addr(addr), socklen(sizeof(addr)){}

    ip_addr(const char* addr, uint16_t port){
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

struct FD_Interface {

    void setOpt(opt_socket lvl, opt_socket opt, void* val){
        int ret=setsockopt(m_sock, lvl, opt, val, sizeof(val));

        if (ret<0)
            throw std::system_error(errno, std::system_category());
    }

protected:
    sockfd m_sock;;
};

struct RW_Interface: FD_Interface {

    void operator<<(const std::string& s){
        writeStr(s+"\r\n");
    }

    void operator>>(std::string& s){
        s=readStr("\r\n");
        s=s.substr(0, s.size()-2);
    }

    void operator<<(const std::vector<char>& vec){
        writePOD(vec.data(), vec.size());
    }

    void operator>>(std::vector<char>& vec){
        readPOD(vec.data(), vec.size());
    }

    std::string readStr(const std::string delim="\r\n"){
        ssize_t ret=0;
        std::string res="";
        char buf[MAX_BUF_LINE]{0};
        for (;;){
            ret=recv(m_sock, buf, MAX_BUF_LINE, MSG_PEEK);

            if (ret<0){
                throw std::system_error(errno, std::system_category());
            }

            if (ret==0){
                return "";
            }

            res.append(buf, ret);
            size_t d=res.find(delim);

            if (d==std::string::npos){
                recv(m_sock, buf, ret, 0);
            } else {
                std::string tmp(buf, ret);

                recv(m_sock, buf, tmp.find(delim)+2, 0);

                return res.substr(0, d+delim.size());
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
                throw std::system_error(errno, std::system_category());
            }

            pos+=static_cast<size_t>(ret);
            toWrite-=static_cast<size_t>(ret);
        }
    }

    void writePOD(const char* const buff, size_t sz){
        int ret=0;
        for (size_t toWrite=sz;toWrite!=0;toWrite-=ret){
            ret=send(m_sock, buff+ret, toWrite, 0);
            if (ret<0)
                throw std::system_error(errno, std::system_category());

        }
    }

    void readPOD(char* buff, unsigned sz){
        int ret=0;
        for (unsigned toRead=sz;toRead!=0;toRead-=ret){
            ret=recv(m_sock, buff+ret, toRead, 0);
            if (ret==0){
                return;
            } else if (ret==-1){
                throw std::system_error(errno, std::system_category());
            }
        }
    }

    int fd(){ return m_sock; }

    void Close(){
        close(m_sock);
    }
};

template <family f, socktype t>
struct Socket {
};

using std::cout;

/* ---------- UNIX TCP ---------- */
template <>
struct Socket<family::local, socktype::stream>:RW_Interface {

    Socket()=default;

    Socket(const char* path){
        m_sock=socket(family::local, socktype::stream, 0);
        m_addr=ip_addr<family::local>(path);
    }

    Socket(const std::string& path){
        m_sock=socket(family::local, socktype::stream, 0);
        m_addr=ip_addr<family::local>(path.c_str());
    }

    Socket(const Socket& op2){
        m_sock=op2.m_sock;
        m_addr=op2.m_addr;
    }

    Socket(Socket&& op2){
        std::swap(m_sock, op2.m_sock);
        std::swap(m_addr, op2.m_addr);
    }

    Socket& operator=(const Socket& op2){
        m_sock=op2.m_sock;
        m_addr=op2.m_addr;

        return *this;
    }

    Socket& operator=(Socket&& op2){
        std::swap(m_sock, op2.m_sock);
        std::swap(m_addr, op2.m_addr);

        return *this;
    }

    void Bind(){
        unlink(m_addr.Path().c_str());

        int ret=bind(m_sock, &m_addr, m_addr.socklen);

        if (ret<0)
            throw std::system_error(errno, std::system_category());
    }

    void Listen(const int queue=30){
        int ret=listen(m_sock, queue);
        if (ret<0)
            throw std::system_error(errno, std::system_category());
    }

    Socket Accept(){
        Socket<family::local, socktype::stream> client;

        for (int ret=0;;ret=accept(m_sock, &client.m_addr, &client.m_addr.socklen)){
            if (ret < 0 && errno==EINTR)
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

    void Connect(std::chrono::milliseconds ms){
        int ret;
        std::future<int> fut=std::async(std::launch::async, connect, m_sock, &m_addr, m_addr.socklen);
        std::future_status status=fut.wait_for(ms);
        if (status==std::future_status::timeout)
            throw SocketException(errtypes::timeout);

        ret=fut.get();
        if (ret<0)
            throw std::system_error(errno, std::system_category());
    }

    void Close(){
        if (close(m_sock)<0){
            throw std::system_error(errno, std::system_category());
        }
    }

    std::string Path(){ return m_addr.Path(); }

    bool state{true};
private:
    ip_addr<family::local> m_addr;
};

/* ---------- UNIX UDP ---------- */
template <>
struct Socket<family::local, socktype::datagram> {

    Socket():m_sock(socket(family::local, socktype::datagram, 0)){};

    Socket(const char* path){
        m_sock=socket(family::local, socktype::datagram, 0);
        m_addr=ip_addr<family::local>(path);
    }

    Socket(const std::string& path){
        m_sock=socket(family::local, socktype::stream, 0);
        m_addr=ip_addr<family::local>(path.c_str());
    }

    Socket(const Socket& op2){
        m_sock=op2.m_sock;
        m_addr=op2.m_addr;
    }

    Socket(Socket&& op2){
        std::swap(m_sock, op2.m_sock);
        std::swap(m_addr, op2.m_addr);
    }

    Socket& operator=(const Socket& op2){
        m_sock=op2.m_sock;
        m_addr=op2.m_addr;

        return *this;
    }

    Socket& operator=(Socket&& op2){
        std::swap(m_sock, op2.m_sock);
        std::swap(m_addr, op2.m_addr);

        return *this;
    }

	void Bind(const std::string& path){
		m_addr=ip_addr<family::local>(path.c_str());

		Bind();
	}

    void Bind(){
        unlink(m_addr.Path().c_str());

        int ret=bind(m_sock, &m_addr, m_addr.socklen);

        if (ret<0)
            throw std::system_error(errno, std::system_category());
    }

    void sendStr(const std::string& msg, ip_addr<local>& target){
        ssize_t ret=0;
        size_t pos=0;
        size_t toWrite=msg.size();
        for (;toWrite!=0;){

            ret=sendto(m_sock, msg.data()+pos, toWrite, 0, &target, target.socklen);

            if (ret<0){
                state=false;
                throw std::system_error(errno, std::system_category());
            }

            pos+=static_cast<size_t>(ret);
            toWrite-=static_cast<size_t>(ret);
        }
    }

    void sendStr(const std::string& msg){
        ssize_t ret=0;
        size_t pos=0;
        size_t toWrite=msg.size();
        for (;toWrite!=0;){

            ret=sendto(m_sock, msg.data()+pos, toWrite, 0, &m_addr, m_addr.socklen);

            if (ret<0){
                state=false;
                throw std::system_error(errno, std::system_category());
            }

            pos+=static_cast<size_t>(ret);
            toWrite-=static_cast<size_t>(ret);
        }
    }

    std::pair<std::string, ip_addr<local>> recvStr(const std::string& delim="\r\n"){
        ssize_t ret=0;
        std::string res="";
        ip_addr<local> client;
        char buf[UDP_MAX_BUF]{0};

        for (;;){
            cout << "blocking in recvfrom\n";
            ret=recvfrom(m_sock, buf, UDP_MAX_BUF, MSG_PEEK, &client, &client.socklen);

            if (ret<0){
                state=false;
                throw std::system_error(errno, std::system_category());
            }

            if (ret==0){
                cout << "ret==0\n";
                state=false;
                break;
            }

            res.append(buf, ret);
            size_t d=res.find(delim);

            cout << "ret: " << ret << " res: " << res << '\n';

            if (d==std::string::npos){
                cout << "no delim\n";
                recvfrom(m_sock, buf, ret, 0, &client, &client.socklen);
            } else {
                cout << "delim found\n";
                std::string tmp(buf, ret);

                recvfrom(m_sock, buf, tmp.find(delim)+delim.size(), 0, &client, &client.socklen);

                return std::make_pair(res.substr(0, d+delim.size()), client);
            }
        }

        return std::make_pair(res, client);
    }

    void sendData(const std::vector<uint8_t>& vec, ip_addr<local>& target){
        size_t toWrite=vec.size();
        int ret=0;
        for (;toWrite!=0;){
            ret=sendto(m_sock, vec.data()+ret, toWrite, 0, &target, target.socklen);

            if (ret<0){
                state=false;
                throw std::system_error(errno, std::system_category());
            }

            toWrite-=ret;
        }
    }

    void sendData(const std::vector<uint8_t>& vec){
        size_t toWrite=vec.size();
        int ret=0;
        for (;toWrite!=0;){
            ret=sendto(m_sock, vec.data()+ret, toWrite, 0, &m_addr, m_addr.socklen);

            if (ret<0){
                state=false;
                throw std::system_error(errno, std::system_category());
            }

            toWrite-=ret;
        }
    }

    std::pair<std::vector<uint8_t>, ip_addr<local>> recvData(const size_t sz){
        std::vector<uint8_t> res(sz);
        size_t toRead=sz;
        ssize_t ret=0;
        ip_addr<local> client;
        for (;toRead!=0;){
            ret=recvfrom(m_sock, res.data()+ret, toRead, 0, &client, &client.socklen);

            if (ret==0){
                break;
            } else if (ret<0){
                throw std::system_error(errno, std::system_category());
            }
            toRead-=ret;
        }

        return std::make_pair(res, client);
    }

    void sendPOD(char* buff, const size_t& sz, ip_addr<local>& target){
        size_t toWrite=sz;
        int ret=0;
        for (;toWrite!=0;){
            ret=sendto(m_sock, buff+ret, toWrite, 0, &target, target.socklen);
            if (ret<0){
                throw std::system_error(errno, std::system_category());
            }
            toWrite-=ret;
        }
    }

    void sendPOD(char* buff, const size_t& sz){
        size_t toWrite=sz;
        int ret=0;
        for (;toWrite!=0;){
            ret=sendto(m_sock, buff+ret, toWrite, 0, &m_addr, m_addr.socklen);
            if (ret<0){
                throw std::system_error(errno, std::system_category());
            }
            toWrite-=ret;
        }
    }

    ip_addr<local> recvPOD(char* buff, const size_t& sz){
        size_t toRead=sz;
        ip_addr<local> client;
        int ret=0;
        for (;toRead!=0;){
            ret=recvfrom(m_sock, buff+ret, toRead, 0, &client, &client.socklen);
            if (ret==0){
                break;
            } else if (ret<0){
                throw std::system_error(errno, std::system_category());
            }
            toRead-=ret;
        }

        return client;
    }

    void Close(){
        unlink(m_addr.Path().c_str());
    }

    std::string Path(){ return m_addr.Path(); }

    bool state{true};
private:
    sockfd m_sock;
    ip_addr<family::local> m_addr;
};

/* ---------- TCP 4/6 ---------- */

template <family f>
struct Socket<f, socktype::stream>: RW_Interface {

    explicit Socket(){}

    Socket(const char* addr, const uint16_t port){
        m_sock = socket(f, socktype::stream, ipproto::tcp);
        m_addr=ip_addr<f>(addr, port);
    }

    Socket(const Socket& op2){
        m_addr=op2.m_addr;
        m_sock=op2.m_sock;
    }

    Socket(Socket&& op2){
        std::swap(m_sock, op2.m_sock);
        std::swap(m_addr, op2.m_addr);
    }

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

    void Bind(const ip_addr<f>& addr){
        m_addr=addr;

        Bind();
    }

    void Bind(){
        int val=1;

//        int ret=setsockopt(m_sock, opt_socket::level, opt_socket::reuseaddr, &val, sizeof(val));


        this->setOpt(opt_socket::level, opt_socket::reuseaddr, &val);

        int ret=bind(m_sock, &m_addr, m_addr.socklen);

//        if (ret==0)
//            ret=bind(m_sock, &m_addr, m_addr.socklen);


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

    void Connect(std::chrono::milliseconds d){
        int ret;
        std::future<int> fut=std::async(std::launch::async, connect, m_sock, &m_addr, m_addr.socklen);
        std::future_status status=fut.wait_for(d);
        if (status==std::future_status::timeout)
            throw SocketException(errtypes::timeout);

        ret=fut.get();
        if (ret<0)
            throw std::system_error(errno, std::system_category());
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

    bool state{true};

private:
    ip_addr<f> m_addr;
};

/* ---------- UDP 4/6 ---------- */

template <family f>
struct Socket<f, socktype::datagram> {

    Socket():m_sock(socket(f, socktype::datagram, ipproto::udp)){}

    Socket(const char* addr, const uint16_t port):
        m_sock(socket(f, socktype::datagram, ipproto::udp)),
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

    void sendStr(const std::string& msg, ip_addr<f>& target){
        ssize_t ret=0;
        size_t pos=0;
        size_t toWrite=msg.size();
        for (;toWrite!=0;){

            ret=sendto(m_sock, msg.data()+pos, toWrite, 0, &target, target.socklen);

            if (ret<0){
                state=false;
                throw std::system_error(errno, std::system_category());
            }

            pos+=static_cast<size_t>(ret);
            toWrite-=static_cast<size_t>(ret);
        }
    }

    void sendStr(const std::string& msg){
        ssize_t ret=0;
        size_t pos=0;
        size_t toWrite=msg.size();
        for (;toWrite!=0;){

            ret=sendto(m_sock, msg.data()+pos, toWrite, 0, &m_addr, m_addr.socklen);

            if (ret<0){
                state=false;
                throw std::system_error(errno, std::system_category());
            }

            pos+=static_cast<size_t>(ret);
            toWrite-=static_cast<size_t>(ret);
        }
    }

    std::pair<std::string, ip_addr<f>> recvStr(const std::string& delim="\r\n"){
        ssize_t ret=0;
        std::string res="";
        ip_addr<f> client;
        char buf[UDP_MAX_BUF]{0};

        for (;;){
            ret=recvfrom(m_sock, buf, UDP_MAX_BUF, MSG_PEEK, &client, &client.socklen);

            if (ret<0){
                state=false;
                throw std::system_error(errno, std::system_category());
            }

            if (ret==0){
                state=false;
                break;
            }

            res.append(buf, ret);
            size_t d=res.find(delim);

            if (d==std::string::npos){
                recvfrom(m_sock, buf, ret, 0, &client, &client.socklen);
            } else {
                std::string tmp(buf, ret);

                recvfrom(m_sock, buf, tmp.find(delim)+delim.size(), 0, &client, &client.socklen);

                return std::make_pair(res.substr(0, d+delim.size()), client);
            }
        }

        return std::make_pair(res, client);
    }

    void sendData(const std::vector<uint8_t>& vec, ip_addr<f>& target){
        size_t toWrite=vec.size();
        int ret=0;
        for (;toWrite!=0;){
            ret=sendto(m_sock, vec.data()+ret, toWrite, 0, &target, target.socklen);

            if (ret<0){
                state=false;
                throw std::system_error(errno, std::system_category());
            }

            toWrite-=ret;
        }
    }

    void sendData(const std::vector<uint8_t>& vec){
        size_t toWrite=vec.size();
        int ret=0;
        for (;toWrite!=0;){
            ret=sendto(m_sock, vec.data()+ret, toWrite, 0, &m_addr, m_addr.socklen);

            if (ret<0){
                state=false;
                throw std::system_error(errno, std::system_category());
            }

            toWrite-=ret;
        }
    }

    std::pair<std::vector<uint8_t>, ip_addr<f>> recvData(const size_t sz){
        std::vector<uint8_t> res(sz);
        size_t toRead=sz;
        ssize_t ret=0;
        ip_addr<f> client;
        for (;toRead!=0;){
            ret=recvfrom(m_sock, res.data()+ret, toRead, 0, &client, &client.socklen);

            if (ret==0){
                break;
            } else if (ret<0){
                throw std::system_error(errno, std::system_category());
            }
            toRead-=ret;
        }

        return std::make_pair(res, client);
    }

    void sendPOD(char* buff, const size_t& sz, ip_addr<f>& target){
        size_t toWrite=sz;
        int ret=0;
        for (;toWrite!=0;){
            ret=sendto(m_sock, buff+ret, toWrite, 0, &target, target.socklen);
            if (ret<0){
                throw std::system_error(errno, std::system_category());
            }
            toWrite-=ret;
        }
    }

    void sendPOD(char* buff, const size_t& sz){
        size_t toWrite=sz;
        int ret=0;
        for (;toWrite!=0;){
            ret=sendto(m_sock, buff+ret, toWrite, 0, &m_addr, m_addr.socklen);
            if (ret<0){
                throw std::system_error(errno, std::system_category());
            }
            toWrite-=ret;
        }
    }

    ip_addr<f> recvPOD(char* buff, const size_t& sz){
        size_t toRead=sz;
        ip_addr<f> client;
        int ret=0;
        for (;toRead!=0;){
            ret=recvfrom(m_sock, buff+ret, toRead, 0, &client, &client.socklen);
            if (ret==0){
                break;
            } else if (ret<0){
                throw std::system_error(errno, std::system_category());
            }
            toRead-=ret;
        }

        return client;
    }

    std::string Addr() const {
        return m_addr.Addr();
    }

    uint16_t Port() const {
        return m_addr.Port();
    }

    bool state{true};

private:
    sockfd m_sock;
    ip_addr<f> m_addr;
};

using ip4_addr=ip_addr<family::ipv4>;
using ip6_addr=ip_addr<family::ipv6>;
using un_addr=ip_addr<family::local>;

using msg_host4=std::pair<std::string, ip4_addr>;
using msg_host6=std::pair<std::string, ip6_addr>;
using msg_unix=std::pair<std::string, un_addr>;

using TCPSocket4=Socket<family::ipv4, socktype::stream>;
using UDPSocket4=Socket<family::ipv4, socktype::datagram>;

using TCPSocket6=Socket<family::ipv6, socktype::stream>;
using UDPSocket6=Socket<family::ipv6, socktype::datagram>;

using UnixTCPSocket=Socket<family::local, socktype::stream>;
using UnixUDPSocket=Socket<family::local, socktype::datagram>;

} //Y namespace

#endif // SOCKET_H

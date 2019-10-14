#include <iostream>
#include <cassert>
#include <socket.hpp>

using namespace Y;

using TCPSocket4=Socket<family::ipv4, socktype::stream>;
using TCPSocket6=Socket<family::ipv6, socktype::stream>;
using UDPSocket4=Socket<family::ipv4, socktype::datagram>;
using UDPSocket6=Socket<family::ipv6, socktype::datagram>;

#define TEST_IPV4_ADDR "192.168.0.1"
#define TEST_IPV4_PORT 1234

int main(int argc, char *argv[])
{
    /* check constructors */
    TCPSocket4 tsock4_0(TEST_IPV4_ADDR, TEST_IPV4_PORT);

    assert(tsock4_0.fd()!=-1);
    assert(tsock4_0.Addr()==TEST_IPV4_ADDR);
    assert(tsock4_0.Port()==TEST_IPV4_PORT);

    TCPSocket4 tsock4_1(tsock4_0);

    assert(tsock4_1.fd()!=-1);
    assert(tsock4_1.Addr()==TEST_IPV4_ADDR);
    assert(tsock4_1.Port()==TEST_IPV4_PORT);

    TCPSocket4 tsock4_2=TCPSocket4(TEST_IPV4_ADDR, TEST_IPV4_PORT);

    assert(tsock4_2.fd()!=-1);
    assert(tsock4_2.Addr()==TEST_IPV4_ADDR);
    assert(tsock4_2.Port()==TEST_IPV4_PORT);

    TCPSocket4 tsock4_3(TCPSocket4(TEST_IPV4_ADDR, TEST_IPV4_PORT));

    assert(tsock4_3.fd()!=-1);
    assert(tsock4_3.Addr()==TEST_IPV4_ADDR);
    assert(tsock4_3.Port()==TEST_IPV4_PORT);

    TCPSocket4 tsock4_4=tsock4_3;

    assert(tsock4_3.fd()!=-1);
    assert(tsock4_3.Addr()==TEST_IPV4_ADDR);
    assert(tsock4_3.Port()==TEST_IPV4_PORT);

    ip_addr<family::local> addr("/tmp/stupid.sock");
    ip_addr<family::local> another=addr;

    assert(another.Path()==addr.Path());

    return 0;
}

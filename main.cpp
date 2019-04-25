#include <iostream>
#include "socket.h"
#include <sstream>
#include <cereal/archives/portable_binary.hpp>
#include <cereal/archives/json.hpp>
#include <cereal/types/vector.hpp>
#include <cereal/types/string.hpp>

using namespace Y;
using namespace Util;
using namespace std;

struct Test{
    Test(int a, double b, vector<int> v, string s):a(a),b(b),v(v),str(s){}

    Test(int a, double b, vector<int> v):a(a),b(b),v(v){}

    uint32_t a;
    double b;
    vector<int> v;
    string str;

    template <typename Ar>
    void serialize(Ar& ar){
        ar(a, b, v, str);
    }
};

int main()
{
    stringstream ss;

    {
//        cereal::PortableBinaryOutputArchive pbin_out(ss);
        cereal::JSONOutputArchive json_out(ss);

        Test t(100, .322, {1, 2, 3}, "Hello");

//        pbin_out(t);
        json_out(t);
    }

    TCPSocket<ipv4> sock("192.168.5.88", 7878);

    sock.Connect();

//    ss.seekg(0, ios::end);

//    sock.writePOD(const_cast<char*>(ss.str().c_str()), ss.tellg());

    cout << "writing\n";
    cout << ss.str();

    sock << ss.str();

    sock.Close();

    return 0;
}

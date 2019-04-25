#include "socket.h"
#include <cereal/archives/portable_binary.hpp>
#include <cereal/archives/json.hpp>
#include <cereal/types/vector.hpp>
#include <cereal/types/string.hpp>
#include <iostream>

using namespace Y;
using namespace std;

struct Test{

    Test()=default;

    Test(int a, double b, vector<int> v, string s):a(a),b(b),v(v),str(s){}

    uint32_t a;
    double b;
    vector<int> v;
    string str;

    template <typename Ar>
    void serialize(Ar& ar){
        ar(a, b, v, str);
    }
};

int main(int argc, char *argv[])
{
    TCPSocket<ipv4> sock("0.0.0.0", 7878);
    sock.Bind();
    sock.Listen();

    char buff[1000];

    for (;;){
        TCPSocket<ipv4> client = sock.Accept();

        string str;

        try {
//            client.readPOD(buff, sizeof(Test));
            str=client.read();
        } catch (Err& e){
            cout << e.strErr() << endl;
        } catch (std::exception& e){
            cout << e.what() << endl;
        }
//        string str(buff, sizeof(Test));
        stringstream ss(Util::nvt_to_str(str));

//        cereal::PortableBinaryInputArchive pbin_in(ss);
        cereal::JSONInputArchive json_in(ss);

        Test t;
//        pbin_in(t);
        json_in(t);

        cout << "recvd \n";

        cout << ss.str();

//        cout << "int: " << t.a << "\n";
//        cout << "double: " << t.b << "\n";
//        cout << "vector ";
//        for (auto x: t.v)
//            cout << x << " ";
//        cout << "\n";
//        cout << "str: " << t.str << "\n";
    }

    sock.Close();

    return 0;
}

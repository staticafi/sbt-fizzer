#include <instrumentation/instrumentation.hpp>

namespace benchmarks::float_if_x_eq_c {


static_assert(sizeof(float) == 4, "we expect 4-byte 'float' type");


static int  mut(float const  x)
{
char* ppp = (char*)&x;
    IF_(x, EQ, -123.4567f) // -123.4567f = 0xC2F6E9D5 hex = 1100 0010 1111 0110 1110 1001 1101 0101 bin
        return 1;
    return 0;
}


DRIVER_()
{
    float x;
    READ_STDIN_(x);
    WRITE_STDOUT_(mut(x));
}


}

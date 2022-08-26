#include <instrumentation/instrumentation.hpp>

namespace benchmarks::int16_if_x_xor_a_eq_b {


static_assert(sizeof(short) == 2, "we expect 2-byte 'short' type");


static int  mut(short const  x)
{
    IF_(x ^ (short)41853, EQ, 12345) // (short)41853 == -23683; Without the cast the TRUE branch is UNREACHABLE!!!
        return 1;
    return 0;
}


DRIVER_()
{
    short x;
    READ_STDIN_(x);
    WRITE_STDOUT_(mut(x));
}


}

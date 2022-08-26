#include <instrumentation/instrumentation.hpp>

namespace benchmarks::int16_if_x_ge_c {


static_assert(sizeof(short) == 2, "we expect 2-byte 'short' type");


static int  mut(short const  x)
{
    IF_(x, GE, 12345)
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

#include <instrumentation/instrumentation.hpp>

namespace benchmarks::int16_if_x_equal_y_c {


static_assert(sizeof(short) == 2, "we expect 2-byte 'short' type");


static int  mut(short const  x, short const  y)
{
    IF_(x, EQ, y - 12345)
        return 1;
    return 0;
}


DRIVER_()
{
    short x,y;
    READ_STDIN_(x);
    READ_STDIN_(y);
    WRITE_STDOUT_(mut(x,y));
}


}

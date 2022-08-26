#include <instrumentation/instrumentation.hpp>

namespace benchmarks::int16_less {


static_assert(sizeof(short) == 2, "we expect 2-byte 'short' type");


static int  mut(short const  x, short const  y)
{
    IF_(x, LT, -10)
        return 1;
    IF_(x, GT, -1)
        return 2;
    IF_(x, GE, y)
        return 3;
    IF_(x + 50, GT, 2*y)
        return 4;
    return 0;
}


DRIVER_()
{
    short x, y;
    READ_STDIN_(x);
    READ_STDIN_(y);
    WRITE_STDOUT_(mut(x, y));
}


}

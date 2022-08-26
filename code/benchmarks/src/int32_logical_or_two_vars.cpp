#include <instrumentation/instrumentation.hpp>

namespace benchmarks::int32_logical_or_two_vars {


static_assert(sizeof(int) == 4, "we expect 4-byte 'int' type");


static int  mut(int const  x, int const  y)
{
    // represents: if (x < 0 || x > 3 || y < 0 || y > 23) return 0; else return 1;
    IF_(x, LT, 0)
        return 0;
    IF_(x, GT, 3)
        return 0;
    IF_(y, LT, 0)
        return 0;
    IF_(y, GT, 23)
        return 0;
    return 1;
}


DRIVER_()
{
    int x, y;
    READ_STDIN_(x);
    READ_STDIN_(y);
    WRITE_STDOUT_(mut(x, y));
}


}

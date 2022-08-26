#include <instrumentation/instrumentation.hpp>

namespace benchmarks::int32_if_x_equal_y_c {


static_assert(sizeof(int) == 4, "we expect 4-byte 'int' type");


static int  mut(int const  x, int const  y)
{
    IF_(x, EQ, y - 123456789)
        return 1;
    return 0;
}


DRIVER_()
{
    int x,y;
    READ_STDIN_(x);
    READ_STDIN_(y);
    WRITE_STDOUT_(mut(x,y));
}


}

#include <instrumentation/instrumentation.hpp>

namespace benchmarks::int8_if_x_equal_y_c {


static_assert(sizeof(char) == 1, "we expect 1-byte 'char' type");


static int  mut(char const  x, char const  y)
{
    IF_(x, EQ, y-123)
        return 1;
    return 0;
}


DRIVER_()
{
    char x,y;
    READ_STDIN_(x);
    READ_STDIN_(y);
    WRITE_STDOUT_(mut(x,y));
}


}

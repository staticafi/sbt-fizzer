#include <instrumentation/instrumentation.hpp>

namespace benchmarks::int32_if_x_equal_c {


static_assert(sizeof(int) == 4, "we expect 4-byte 'int' type");


static int  mut(int const  x)
{
    IF_(x, EQ, 123456789)
        return 1;
    return 0;
}


DRIVER_()
{
    int x;
    READ_STDIN_(x);
    WRITE_STDOUT_(mut(x));
}


}

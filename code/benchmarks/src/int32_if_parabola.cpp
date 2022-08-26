#include <instrumentation/instrumentation.hpp>

namespace benchmarks::int32_if_parabola {


static_assert(sizeof(int) == 4, "we expect 4-byte 'int' type");


static int  mut(int const  x)
{
    IF_(-x*x+6*x-8, EQ, 0)  // Roots are: 2 and 4.
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

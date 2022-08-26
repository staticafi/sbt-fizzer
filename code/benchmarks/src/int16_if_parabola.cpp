#include <instrumentation/instrumentation.hpp>

namespace benchmarks::int16_if_parabola {


static_assert(sizeof(short) == 2, "we expect 2-byte 'short' type");


static int  mut(short const  x)
{
    IF_(-x*x+(short)6*x-(short)8, EQ, (short)0)  // Roots are: 2 and 4.
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

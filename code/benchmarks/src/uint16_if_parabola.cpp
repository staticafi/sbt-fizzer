#include <instrumentation/instrumentation.hpp>

namespace benchmarks::uint16_if_parabola {


static_assert(sizeof(unsigned short) == 2, "we expect 2-byte 'unsigned short' type");


static int  mut(unsigned short const  x)
{
    IF_(-x*x+(unsigned short)6*x-(unsigned short)8, EQ, (unsigned short)0)  // Roots are: 2 and 4.
        return 1;
    return 0;
}


DRIVER_()
{
    unsigned short x;
    READ_STDIN_(x);
    WRITE_STDOUT_(mut(x));
}


}

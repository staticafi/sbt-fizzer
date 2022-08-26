#include <instrumentation/instrumentation.hpp>

namespace benchmarks::uint32_if_parabola {


static_assert(sizeof(unsigned int) == 4, "we expect 4-byte 'unsigned int' type");


static int  mut(unsigned int const  x)
{
long double xxx = (long double)x;           //              1 431 655 765 == x
long double fff = 6.0*xxx-8.0-xxx*xxx;      // -2 049 638 220 867 800 643 == fff
unsigned int iii = 6U*x-8U-x*x;             //              3 340 530 109 == iii

    IF_(6U*x-8U-x*x, EQ, 0U)  // Roots are: 2 and 4.
        return 1;
    return 0;
}


DRIVER_()
{
    unsigned int x;
    READ_STDIN_(x);
    WRITE_STDOUT_(mut(x));
}


}

#include <instrumentation/instrumentation.hpp>

namespace benchmarks::bool_flag_one_and_two {


static_assert(sizeof(short) == 2, "we expect 2-byte 'short' type");


static bool  mut(short const  x1, short const  y1, short const  x2, short const  y2)
{
    bool cond_1, cond_2;

    IF_(x1, EQ, y1 + 123)
        cond_1 = true;
    else
        cond_1 = false;

    IF_(x2, NE, y2 + 123)
        cond_2 = true;
    else
        cond_2 = false;

    IF_(cond_1, EQ, true)
        IF_(cond_2, EQ, true)
            return true;
    return false;
}


DRIVER_()
{
    short x1, y1, x2, y2;
    READ_STDIN_(x1);
    READ_STDIN_(y1);
    READ_STDIN_(x2);
    READ_STDIN_(y2);
    WRITE_STDOUT_(mut(x1, y1, x2, y2));
}


}

#include <instrumentation/instrumentation.hpp>

namespace benchmarks::int32_ackermann {


static_assert(sizeof(int) == 4, "we expect 4-byte 'int' type");


static int  ackermann(int const  x, int const  y)
{
    IF_(x, EQ, 0)
        return y + 1;
    IF_(y, EQ, 0)
        return ackermann(x - 1,1);
    return ackermann(x - 1,ackermann(x,y - 1));
}


static int  mut(int const  x, int const  y)
{
    // represents: if (x < 0 || x > 3 || y < 0 || y > 23) return 0;
    IF_(x, LT, 0)
        return 0;
    IF_(x, GT, 3)
        return 0;
    IF_(y, LT, 0)
        return 0;
    IF_(y, GT, 23)
        return 0;

    int r = ackermann(x,y);

    // represents: if (x < 2 || r >= 4) return 1;
    IF_(x, LT, 2)
        return 1;
    IF_(r, GE, 4)
        return 1;

    return 2;
}


DRIVER_()
{
    int x, y;
    READ_STDIN_(x);
    READ_STDIN_(y);
    WRITE_STDOUT_(mut(x, y));
}


}

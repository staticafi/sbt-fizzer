#include <instrumentation/instrumentation.hpp>

namespace benchmarks::int8_if_x_xor_a_eq_b {


static_assert(sizeof(char) == 1, "we expect 1-byte 'char' type");


static int  mut(char const  x)
{
    IF_(x ^ 83, EQ, 123)
        return 1;
    return 0;
}


DRIVER_()
{
    char x;
    READ_STDIN_(x);
    WRITE_STDOUT_(mut(x));
}


}

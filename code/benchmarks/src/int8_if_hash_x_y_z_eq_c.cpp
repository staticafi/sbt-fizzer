#include <instrumentation/instrumentation.hpp>

namespace benchmarks::int8_if_hash_x_y_z_eq_c {


static_assert(sizeof(char) == 1, "we expect 1-byte 'char' type");


static void hash_combine(unsigned int& seed, char const  x)
{
    seed ^= ((unsigned int)x * 977U) + 0x9e3779b9U + (seed << 6) + (seed >> 2);
}


static int  mut(char const  x, char const  y, char const  z)
{
    unsigned int seed0, seed1;

    seed0 = 73910U;
    hash_combine(seed0, -24);
    hash_combine(seed0, 56);
    hash_combine(seed0, -120);

    seed1 = 73910U;
    hash_combine(seed1, x);
    hash_combine(seed1, y);
    hash_combine(seed1, z);

    IF_(seed1, EQ, seed0)
        return 1;
    return 0;
}


DRIVER_()
{
    char x,y,z;
    READ_STDIN_(x);
    READ_STDIN_(y);
    READ_STDIN_(z);
    WRITE_STDOUT_(mut(x,y,z));
}


}

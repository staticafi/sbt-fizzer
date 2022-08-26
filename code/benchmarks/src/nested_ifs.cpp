#include <instrumentation/instrumentation.hpp>

namespace benchmarks::nested_ifs {


static bool mut(char  data[4])
{
    IF_(data[0], EQ, 'b')
        IF_(data[1], EQ, 'a')
            IF_(data[2], EQ, 'd')
                IF_(data[3], EQ, '!')
                    return true;
    return false;
}


DRIVER_()
{
    char  data[4];

    READ_STDIN_(data[0]);
    READ_STDIN_(data[1]);
    READ_STDIN_(data[2]);
    READ_STDIN_(data[3]);

    WRITE_STDOUT_(mut(data));
}


}

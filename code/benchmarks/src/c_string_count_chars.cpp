#include <instrumentation/instrumentation.hpp>

namespace benchmarks::c_string_count_chars {


static bool  mut(char const* const  c_string)
{
    int i = 0, k = 0;
    while (true)
    {
        IF_(c_string[i], EQ, '\0')
            break;
        IF_(c_string[i], EQ, 'A')
            ++k;
        ++i;
    }
    IF_(k, EQ, 5)
        return true;
    return false;
}


DRIVER_()
{
    short n;
    char s[50];
    READ_STDIN_(n);
    IF_(n, LE, 0)
        return;
    IF_(n, GE, sizeof(s) / sizeof(s[0]))
        return;
    FOR_(short i = 0, i, LT, n, ++i)
        READ_STDIN_(s[i]);
    IF_(s[n-1], NE, '\0')
        return;

    WRITE_STDOUT_(mut(s));
}


}

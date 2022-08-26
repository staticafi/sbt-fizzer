#include <instrumentation/instrumentation.hpp>
#include <string>

namespace benchmarks::c_string_parse_two_ints {


static int  parse_int(char const* const  c_string, char const  which, char const  terminal, int*  result)
{
    int idx = 0, sign = 1, end = 0, i = 0, exp = 1;
    IF_(c_string[idx], EQ, '\0')
        return -1;
    IF_(c_string[idx], NE, which)
        return -1;
    ++idx;
    IF_(c_string[idx], EQ, '\0')
        return -1;
    IF_(c_string[idx], NE, '=')
        return -1;
    ++idx;
    IF_(c_string[idx], EQ, '\0')
        return -1;
    IF_(c_string[idx], EQ, '-')
    {
        sign = -1;
        ++idx;
    }
    else
    {
        IF_(c_string[idx], EQ, '+')
            ++idx;
    }
    end = idx;
    while (true)
    {
        IF_(c_string[idx], EQ, terminal)
            break;
        IF_(c_string[idx], EQ, '\0')
            return -1;
        IF_(c_string[idx], LT, '0')
            return -1;
        IF_(c_string[idx], GT, '9')
            return -1;
        ++idx;
        IF_(idx - end, GT, 3)
            return -1;
    }
    IF_(idx, EQ, end)
        return -1;
    *result = 0;
    i = idx;
    while (true)
    {
        IF_(i, EQ, end)
            return idx;
        --i;
        *result += (c_string[i] - '0') * exp;
        exp *= 10;
    }
}


static bool  mut(char const* const  c_string)
{
    int  idx = 0, idx_tmp, x, y;
    idx_tmp = parse_int(c_string + idx, 'x', ';', &x);
    IF_(idx_tmp, EQ, -1)
        return false;
    idx += idx_tmp + 1;
    idx_tmp = parse_int(c_string + idx, 'y', '\0', &y);
    IF_(idx_tmp, EQ, -1)
        return false;
    return true;
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

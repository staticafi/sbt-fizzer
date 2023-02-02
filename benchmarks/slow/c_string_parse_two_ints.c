#include <stdbool.h>

extern char __VERIFIER_nondet_char();
extern short __VERIFIER_nondet_short();

static int  parse_int(char const* const  c_string, char const  which, char const  terminal, int*  result)
{
    int idx = 0, sign = 1, end = 0, i = 0, exp = 1;
    if (c_string[idx] == '\0')
        return -1;
    if (c_string[idx] != which)
        return -1;
    ++idx;
    if (c_string[idx] == '\0')
        return -1;
    if (c_string[idx] != '=')
        return -1;
    ++idx;
    if (c_string[idx] == '\0')
        return -1;
    if (c_string[idx] == '-')
    {
        sign = -1;
        ++idx;
    }
    else
    {
        if (c_string[idx] == '+')
            ++idx;
    }
    end = idx;
    while (true)
    {
        if (c_string[idx] == terminal)
            break;
        if (c_string[idx] == '\0')
            return -1;
        if (c_string[idx] < '0')
            return -1;
        if (c_string[idx] > '9')
            return -1;
        ++idx;
        if (idx - end > 3)
            return -1;
    }
    if (idx == end)
        return -1;
    *result = 0;
    i = idx;
    while (true)
    {
        if (i == end)
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
    if (idx_tmp == -1)
        return false;
    idx += idx_tmp + 1;
    idx_tmp = parse_int(c_string + idx, 'y', '\0', &y);
    if (idx_tmp == -1)
        return false;
    return true;
}


int main()
{
    short n;
    char s[50];
    n = __VERIFIER_nondet_short();
    if (n <= 0)
        return -1;
    if (n >= sizeof(s) / sizeof(s[0]))
        return -1;
    for (short i = 0; i < n; ++i)
        s[i] = __VERIFIER_nondet_char();
    if (s[n-1] != '\0')
        return -1;

    return (int)mut(s);
}

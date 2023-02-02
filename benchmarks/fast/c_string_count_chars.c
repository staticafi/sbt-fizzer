#include <stdbool.h>

extern char __VERIFIER_nondet_char();
extern short __VERIFIER_nondet_short();

int main()
{
    char s[50];
    {
        short n;
        n = __VERIFIER_nondet_short();
        if (n <= 0)
            return -1;
        if (n >= sizeof(s) / sizeof(s[0]))
            return -1;
        for (short i = 0; i < n; ++i)
            s[i] = __VERIFIER_nondet_char();
        if (s[n-1] != '\0')
            return -1;
    }
    {
        int i = 0, k = 0;
        while (true)
        {
            if (s[i] == '\0')
                break;
            if (s[i] == 'A')
                ++k;
            ++i;
        }
        if (k == 5)
            return 1;
        return 0;
    }
}

#include <stdbool.h>

extern char __VERIFIER_nondet_char();
extern short __VERIFIER_nondet_short();


int main()
{
    char s[ 50 ];
    {
        short n;
        n = __VERIFIER_nondet_short();
        if ( n <= 0 ) // ID: 1
            return -1;
        if ( n >= sizeof( s ) / sizeof( s[ 0 ] ) ) // ID: 2
            return -1;
        for ( short i = 0; i < n; ++i ) // ID: 3
            s[ i ] = __VERIFIER_nondet_char();
        if ( s[ n - 1 ] != '\0' ) // ID: 4
            return -1;
    }
    {
        int i = 0, k = 0;
        while ( true ) {
            if ( s[ i ] == '\0' ) // ID: 5
                break;
            if ( s[ i ] == 'A' ) // ID: 6
                ++k;
            ++i;
        }

        if ( k >= 6 ) // ID: 7
        {
            if ( k > 8 ) // ID: 8
            {
                if ( 12 < k ) // ID: 9
                {
                    if ( k == 13 ) // ID: 10
                        return 1;
                }

                if ( k >= 16 ) // ID: 11
                {
                    if ( k == 30 ) // ID: 12
                        return 1;
                }
            }
        }

        return 0;
    }
}
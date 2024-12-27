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
            if ( s[ i ] == 'B' ) // ID: 7
                --k;
            ++i;
        }
        if ( k == 10 ) // ID: 8
            return 1;
        return 0;
    }
}

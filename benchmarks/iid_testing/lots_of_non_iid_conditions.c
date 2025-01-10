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
        if ( s[ 0 ] == 'A' ) // ID: 5
            return 1;

        if ( s[ 1 ] == 'A' ) // ID: 6
            return 1;

        if ( s[ 2 ] == 'A' ) // ID: 7
            return 1;

        if ( s[ 3 ] == 'A' ) // ID: 8
            return 1;

        if ( s[ 4 ] == 'A' ) // ID: 9
            return 1;

        if ( s[ 5 ] == 'A' ) // ID: 10
            return 1;

        if ( s[ 6 ] == 'A' ) // ID: 11
            return 1;

        if ( s[ 7 ] == 'A' ) // ID: 12
            return 1;

        if ( s[ 8 ] == 'A' ) // ID: 13
            return 1;

        if ( s[ 9 ] == 'A' ) // ID: 14
            return 1;

        return 0;
    }
}

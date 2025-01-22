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
        if ( k == 10 ) // ID: 7
            return 1;

        i = 0;
        k = 0;
        while ( true ) {
            if ( s[ i ] == '\0' ) // ID: 8
                break;
            if ( s[ i ] == 'B' ) // ID: 9
                ++k;
            ++i;
        }
        if ( k > 10 ) // ID: 10
            return 1;

        i = 0;
        k = 0;
        while ( true ) {
            if ( s[ i ] == '\0' ) // ID: 11
                break;
            if ( s[ i ] == 'C' ) // ID: 12
                ++k;
            ++i;
        }
        if ( k >= 10 ) // ID: 13
            return 1;

        i = 0;
        k = 0;
        while ( true ) {
            if ( s[ i ] == '\0' ) // ID: 14
                break;
            if ( s[ i ] == 'D' ) // ID: 15
                ++k;
            ++i;
        }
        // if ( 10 > k ) // ID: 16
        if ( 10 < k ) // ID: 16
            return 1;

        i = 0;
        k = 0;
        while ( true ) {
            if ( s[ i ] == '\0' ) // ID: 17
                break;
            if ( s[ i ] == 'E' ) // ID: 18
                ++k;
            ++i;
        }
        if ( 10 <= k ) // ID: 19
            return 1;

        return 0;
    }
}

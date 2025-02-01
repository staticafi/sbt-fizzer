#include <stdbool.h>

extern char __VERIFIER_nondet_char();
extern short __VERIFIER_nondet_short();


int main()
{
    short loop_count_1;
    loop_count_1 = __VERIFIER_nondet_short();
    short loop_count_2;
    loop_count_2 = __VERIFIER_nondet_short();

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
        if ( loop_count_1 > 20 ) // ID: 5
            return -1;

        if ( loop_count_2 > 20 ) // ID: 6
            return -1;

        int i = 0, k = 0;

        for ( short index_1 = 0; index_1 < loop_count_1; ++index_1 ) {     // ID: 7
            for ( short index_2 = 0; index_2 < loop_count_2; ++index_2 ) { // ID: 8
                i = 0;
                while ( true ) {
                    if ( s[ i ] == '\0' ) // ID: 9
                        break;
                    if ( s[ i ] == 'A' ) // ID: 10
                        ++k;
                    ++i;
                }
            }

            i = 0;
            while ( true ) {
                if ( s[ i ] == '\0' ) // ID: 11
                    break;
                if ( s[ i ] == 'B' ) // ID: 12
                    --k;
                ++i;
            }
        }

        if ( k == 10 ) // ID: 13
            return 1;

        return 0;
    }
}

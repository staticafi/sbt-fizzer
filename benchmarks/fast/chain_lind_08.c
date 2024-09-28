extern double __VERIFIER_nondet_double(void);

int main() {
    double x0 = __VERIFIER_nondet_double();
    double x1 = __VERIFIER_nondet_double();
    double x2 = __VERIFIER_nondet_double();

    // a solution:  x0 = 1.034391313382053035, x1 = 0.3557288269509288892, x2 = 0.6741122319446676281;

    if (  x0 - 0.95*x1 - 4*x2 + 2 == 0.0)
    if (2*x0 - 3.00*x1        - 1 >  0.0)
        return 1;

    return 0;
}

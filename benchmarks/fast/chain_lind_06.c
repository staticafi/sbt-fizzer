extern double __VERIFIER_nondet_double(void);

int main() {
    double x0 = __VERIFIER_nondet_double();
    double x1 = __VERIFIER_nondet_double();
    double x2 = __VERIFIER_nondet_double();

    // a solution:  x0 = 0.3465200303330524534, x1 = -0.2057466852737202812, x2 = 0.8160367564331251211;

    if (1.12*x0 - 3.14*x1 - 4*x2 + 2.23 == 0.0)
    if (2.31*x0 - 3.40*x1        - 1.50 == 0.0)
        return 1;

    return 0;
}

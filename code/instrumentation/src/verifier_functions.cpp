#include <iomodels/instrumentation_callbacks.hpp>

extern "C" {
int __VERIFIER_nondet_int() {
    int n;
    iomodels::on_read_stdin(1, (natural_8_bit*) &n, sizeof(n));
    return n;
}
}
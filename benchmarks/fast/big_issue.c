extern void abort(void);
extern int __VERIFIER_nondet_int(void);

void reach_error(void) {
  abort();
}

void __VERIFIER_assert(int cond) {
  if (!cond) {
    reach_error();
  }
}

int main() {
  int x = __VERIFIER_nondet_int();
  int y = __VERIFIER_nondet_int();
  int z = __VERIFIER_nondet_int();
  if (!(x == y && x >= 0 && x+y+z==0))
    return 0;
  while (x > 0) {
    x--;
    y--;
    z++;
    z++;
  }
  __VERIFIER_assert(z<=0);
  return 0;
}

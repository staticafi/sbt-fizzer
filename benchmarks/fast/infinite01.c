extern int __VERIFIER_nondet_int();
extern void abort(void);
typedef unsigned int size_t;
extern void *malloc (size_t __size);
extern void __assert_fail(const char *, const char *, unsigned int, const char *) __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__noreturn__));

void reach_error() { __assert_fail("0", "infinite01.c", 3, "reach_error"); }

typedef struct node {
    int val;
    struct node *next;
} Node;
int main() {
    Node *p, *list = malloc(sizeof(*list));
    Node *tail = list;
    list->next = ((void *)0);
    list->val = 10;
    while (__VERIFIER_nondet_int()) {
        int x = __VERIFIER_nondet_int();
        if (x < 10 || x > 20) continue;
        p = malloc(sizeof(*p));
        tail->next = p;
        p->next = ((void *)0);
        p->val = x;
        tail = p;
    }
    while (1) {
        for (p = list; p!= ((void *)0); p = p->next) {
            if (!(p->val <= 20 && p->val >= 10))
                {reach_error();}
            if (p->val < 20) p->val++;
            else p->val /= 2;
        }
    }
}

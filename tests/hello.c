#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int fib(int n) { return n < 2 ? n : fib(n - 1) + fib(n - 2); }

static const char *classify(int v) {
    switch (v) {
        case 0: return "zero";
        case 1: return "one";
        case 2: return "two";
        default: return v < 0 ? "negative" : "many";
    }
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s <n>\n", argv[0]);
        exit(2);
    }
    int n = atoi(argv[1]);
    char buf[64];
    snprintf(buf, sizeof buf, "fib(%d) = %d", n, fib(n));
    puts(buf);
    printf("class: %s\n", classify(n));
    return 0;
}

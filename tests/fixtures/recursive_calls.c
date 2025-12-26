// tests/fixtures/recursive_calls.c
// Test binary with recursive function calls
// Compile with: gcc -g -O0 -o recursive_calls recursive_calls.c

#include <stdio.h>

int factorial(int n) {
    if (n <= 1) return 1;
    return n * factorial(n - 1);
}

int fibonacci(int n) {
    if (n <= 1) return n;
    return fibonacci(n - 1) + fibonacci(n - 2);
}

int main() {
    printf("5! = %d\n", factorial(5));
    printf("fib(10) = %d\n", fibonacci(10));
    return 0;
}

#include <stdio.h>
#include <stdlib.h>

static void checkpoint(const char *msg) {
    puts(msg);
    getchar();
}

int main(void) {
    void *a = malloc(0x20);
    void *b = malloc(0x20);
    void *c = malloc(0x20);
    printf("a=%p\nb=%p\nc=%p\n", a, b, c);

    free(a);
    free(b);
    printf("freed a=%p then b=%p\n", a, b);
    checkpoint("after two frees");

    /*
     * Educational fastbin-dup-like shape: attempt to free a again after an
     * intervening free. Modern glibc hardening may detect this and abort.
     * Heapify's tracker should still classify the repeated pointer.
     */
    free(a);
    printf("freed a=%p again\n", a);
    checkpoint("after duplicate free shape");

    free(c);
    return 0;
}

#include <stdio.h>
#include <stdlib.h>

static void checkpoint(const char *msg) {
    puts(msg);
    getchar();
}

int main(void) {
    void *a = malloc(0x30);
    void *b = malloc(0x30);
    printf("a=%p\nb=%p\n", a, b);

    free(a);
    printf("freed a=%p once\n", a);
    checkpoint("after first free");

    /*
     * Intentional educational double-free shape: the same user pointer is
     * passed to free twice. Modern glibc may abort here; Heapify should still
     * report the allocator event and tracker warning before process exit.
     */
    free(a);
    printf("freed a=%p twice\n", a);
    checkpoint("after second free");

    free(b);
    return 0;
}

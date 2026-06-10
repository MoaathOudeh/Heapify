#include <stdlib.h>

int main(void) {
    void *a = malloc(0x500);
    void *guard = malloc(0x20);

    free(a);

    void *b = malloc(0x1000);

    (void)b;
    (void)guard;
    return 0;
}

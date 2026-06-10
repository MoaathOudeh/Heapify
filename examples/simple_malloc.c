#include <stdlib.h>

int main(void) {
    void *a = malloc(0x20);
    void *b = malloc(0x30);

    free(a);

    void *c = malloc(0x20);

    free(b);
    free(c);

    return 0;
}

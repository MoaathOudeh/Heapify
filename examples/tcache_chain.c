#include <stdlib.h>

int main(void) {
    void *a = malloc(0x20);
    void *b = malloc(0x20);
    void *c = malloc(0x20);

    free(a);
    free(b);
    free(c);

    return 0;
}

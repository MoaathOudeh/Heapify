#include <stdlib.h>

int main(void) {
    void *a = malloc(0x20);
    a = realloc(a, 0x80);
    free(a);
    return 0;
}


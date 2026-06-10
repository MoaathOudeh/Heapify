#include <stdlib.h>

int main(void) {
    void *a = calloc(4, 0x10);
    free(a);
    return 0;
}


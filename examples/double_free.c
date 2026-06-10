#include <stdlib.h>

int main(void) {
    void *p = malloc(0x20);
    free(p);
    free(p);
    return 0;
}


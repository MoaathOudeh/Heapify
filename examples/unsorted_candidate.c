#include <stdlib.h>

int main(void) {
    void *a = malloc(0x500);
    void *guard = malloc(0x20);

    free(a);

    (void)guard;
    return 0;
}

#include <stdlib.h>

int main(void) {
    void *p[10];

    for (int i = 0; i < 10; i++) {
        p[i] = malloc(0x20);
    }

    /*
     * Tcache usually takes the first 7 frees. The guard chunk helps prevent
     * top consolidation, so later frees may form a fastbin chain.
     */
    void *guard = malloc(0x100);

    for (int i = 0; i < 10; i++) {
        free(p[i]);
    }

    (void)guard;
    return 0;
}

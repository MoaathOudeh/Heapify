#include <stdlib.h>

int main(void) {
    void *p[8];

    for (int i = 0; i < 8; i++) {
        p[i] = malloc(0x20);
    }

    /*
     * Tcache usually takes the first 7 frees. The guard chunk helps prevent
     * top consolidation, so the 8th free may reach fastbin.
     */
    void *guard = malloc(0x100);

    for (int i = 0; i < 8; i++) {
        free(p[i]);
    }

    (void)guard;
    return 0;
}

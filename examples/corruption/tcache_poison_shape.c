#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

static void checkpoint(const char *msg) {
    puts(msg);
    getchar();
}

int main(void) {
    void *a = malloc(0x20);
    void *b = malloc(0x20);
    printf("a=%p\nb=%p\n", a, b);

    free(a);
    free(b);
    printf("freed a=%p and b=%p into the same tcache-sized class\n", a, b);
    checkpoint("after tcache frees");

    /*
     * Educational suspicious shape only: corrupt the first word of a freed
     * tcache-sized chunk so a later allocator-view scan may see a malformed
     * next pointer. This is not a payload and does not request an allocation
     * from the poisoned list.
     */
    *(uintptr_t *)b = 0x4141414141414141ULL;
    printf("overwrote freed chunk b next field with marker\n");
    checkpoint("after tcache shape");

    return 0;
}

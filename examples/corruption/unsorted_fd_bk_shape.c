#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

static void checkpoint(const char *msg) {
    puts(msg);
    getchar();
}

int main(void) {
    void *a = malloc(0x500);
    void *guard = malloc(0x20);
    printf("a=%p\nguard=%p\n", a, guard);

    free(a);
    printf("freed large chunk a=%p toward unsorted-bin handling\n", a);
    checkpoint("after unsorted-sized free");

    /*
     * Educational fd/bk suspicious shape only: modify words in freed user
     * storage where unsorted-bin links are commonly visible. This is not an
     * unlink payload and does not try to drive allocator control flow.
     */
    ((uintptr_t *)a)[0] = 0x4242424242424242ULL;
    ((uintptr_t *)a)[1] = 0x4343434343434343ULL;
    printf("overwrote freed chunk a link-shaped words\n");
    checkpoint("after unsorted fd/bk shape");

    free(guard);
    return 0;
}

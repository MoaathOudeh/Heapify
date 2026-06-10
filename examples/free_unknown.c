#include <stdint.h>
#include <stdlib.h>

int main(void) {
    uintptr_t fake = 0x4141414141414141;
    free((void *)fake);
    return 0;
}


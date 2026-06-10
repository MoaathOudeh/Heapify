#include <stdlib.h>

int main(void) {
    void *p = NULL;
    free(p);
    return 0;
}

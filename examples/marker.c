#include <stdio.h>

void marker(void) {
    puts("marker hit");
}

int main(void) {
    marker();
    marker();
    return 0;
}


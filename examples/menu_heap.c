#include <stdio.h>
#include <stdlib.h>

int main(void) {
    void *slots[4] = {0};

    for (;;) {
        int choice = 0;
        int index = 0;
        size_t size = 0;

        printf("1) malloc\n2) free\n3) exit\n> ");
        fflush(stdout);

        if (scanf("%d", &choice) != 1) {
            break;
        }

        if (choice == 1) {
            if (scanf("%d %zu", &index, &size) != 2) {
                break;
            }
            if (index >= 0 && index < 4) {
                slots[index] = malloc(size);
                printf("slot[%d] = %p\n", index, slots[index]);
            }
        } else if (choice == 2) {
            if (scanf("%d", &index) != 1) {
                break;
            }
            if (index >= 0 && index < 4) {
                free(slots[index]);
                slots[index] = NULL;
                printf("freed slot[%d]\n", index);
            }
        } else if (choice == 3) {
            break;
        }
    }

    for (int i = 0; i < 4; i++) {
        free(slots[i]);
    }

    return 0;
}

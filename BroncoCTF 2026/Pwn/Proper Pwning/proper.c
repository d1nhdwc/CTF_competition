#include <stdio.h>
#include <string.h>

#define CLOSED 0
#define ALIVE 41

void init() {
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
}

void win() {
    printf("\n[-] oh my goodness, you're the greatest C pwner of all time. yoshie bows down to your prowess.\n");
    system("/bin/cat flag.txt");
    exit(0);
}

void treasure_room() {
    char buffer[6767]; // thought it couldn't get funnier, huh?

    gets(buffer);

    printf("\nTREASURE?\n");
    return;
}

int gate3() {
    volatile int gate = CLOSED;
    char buffer[67]; // HAHAHAHAHAHA you so funny.

    gets(buffer);
    if (gate == CLOSED) {
        printf("\n[-] Try again. Gate 3 slams shut in your face.\n");
        return -1;
    } else if (gate == 13371337) {
        printf("\n[+] Gate 3 opens, and you find some treasure. It says 'win() is that way, located at %p'\n", (void *)win);
        return 1;
    }
    else {
        printf("\n[-] Try again. Gate 3 creaks, but remains shut.");
        return -1;
    }
}

int gate2() {
    volatile int gate = CLOSED;
    volatile int baby_chicken = ALIVE;
    long buffer[64];

    gets(buffer);
    if (baby_chicken != ALIVE) {
        printf("\n[-] YOU KILLED THE CHICKEN. Gate 2 retaliates aggressively.\n");
        return -1;
    }
    if (gate == CLOSED) {
        printf("\n[-] Try again. Gate 2 refuses to open.\n");
        return -1;
    } else {
        printf("\n[+] Well done. Gate 2 opens.\n");
        return 1;
    }
}

int gate1() {
    volatile int gate = CLOSED;
    int buffer[64];

    gets(buffer);
    if (gate == CLOSED) {
        printf("\n[-] Sorry, Gate 1 refuses to open.\n");
        return -1;
    } else {
        printf("\n[+] Well done. Gate 1 opens.\n");
        return 1;
    }

}

int main(int argc, char *argv[]) {
    init();

    if (gate1() == -1) {
        return 0;
    }
    if (gate2() == -1) {
        return 0;
    }
    if (gate3() == -1)  {
        return 0;
    }
    treasure_room();
    printf("\nNo :(\n");
    return 0;
}

// gcc proper.c -o proper -fno-stack-protector -z execstack -no-pie
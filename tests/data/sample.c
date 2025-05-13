#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int add(int a, int b) { return a + b; }

int factorial(int n) {
    if (n <= 1) return 1;
    return n * factorial(n - 1);
}

void fill_array(int* arr, int size) {
    for (int i = 0; i < size; i++) {
        if (i % 2 == 0)
            arr[i] = i * i;
        else
            arr[i] = -i;
    }
}

int compute(int x) {
    switch (x % 4) {
        case 0:
            return add(x, 10);
        case 1:
            return factorial(x % 6);
        case 2:
            return x * x;
        case 3:
            return x - 5;
        default:
            return 0;
    }
}

void complicated(int n) {
    if (n < 0) return;

    int* buffer = (int*)malloc(n * sizeof(int));
    if (!buffer) return;

    fill_array(buffer, n);

    for (int i = 0; i < n; i++) {
        int val = compute(buffer[i]);
        printf("Result[%d] = %d\n", i, val);
    }

    free(buffer);
}

typedef enum { RED, GREEN, BLUE, UNKNOWN_COLOR = 255 } Color;

typedef struct {
    uint32_t is_enabled : 1;
    unsigned int mode : 3;
    uint64_t reserved : 4;
} Flags;

typedef union {
    int int_val;
    float float_val;
    char str_val[8];
} ValueUnion;

typedef struct {
    int id;
    Color color;
    Flags flags;
    ValueUnion data;
} Item;

typedef struct Deep {
    struct {
        struct {
            int a;
            char b[3];
            struct {
                int c;
                union {
                    uint64_t long_val;
                    uint8_t array_val[8];
                    struct {
                        uint32_t bf1 : 1;
                        uint32_t bf2 : 5;
                        uint32_t bf3 : 2;
                        uint32_t bf4 : 20;
                        uint32_t bf5 : 4;
                        uint32_t bf6 : 32;
                    } bitfield_val;
                } val_union;
                char inline_data[16];
            } nested;
        } inner;
        uint8_t data[20];
    } core;
    int trailing;
} DeepStruct;

typedef struct {
    uint64_t count;
    union {
        uint16_t i_arr[4];
        float f_arr[4];
    } data;
    Item items[];
} ComboStruct;

void test_flags(Flags f) {
    printf("Flags: enabled=%u, mode=%u, reserved=%u\n", f.is_enabled, f.mode,
           f.reserved);
}

void test_union(ValueUnion vu) {
    vu.float_val = 3.14f;
    printf("Union as float: %f\n", vu.float_val);
    vu.int_val = 42;
    printf("Union as int: %d\n", vu.int_val);
    strcpy(vu.str_val, "abc");
    printf("Union as string: %s\n", vu.str_val);
}

const char* color_name(Color c) {
    switch (c) {
        case RED:
            return "Red";
        case GREEN:
            return "Green";
        case BLUE:
            return "Blue";
        default:
            return "Unknown";
    }
}

void test_item(Item* item) {
    printf("Item ID: %d, Color: %s\n", item->id, color_name(item->color));
    test_flags(item->flags);
    test_union(item->data);
}

void test_deep_struct(DeepStruct* ds) {
    ds->core.data[5] = 0xff;
    ds->core.data[2] = 0xa5;
    ds->core.data[17] = 0x5a;
    ds->core.inner.a = 123;
    ds->core.inner.b[0] = 'x';
    ds->core.inner.nested.c = 999;
    ds->core.inner.nested.val_union.long_val = 0xaabbccddeeff9988;
    ds->core.inner.nested.val_union.array_val[0] = 10;
    strcpy(ds->core.inner.nested.inline_data, "test");
    printf(
        "DeepStruct a: %d, c: %d, inline_data: %s, bitfield %u %u %u %u %u "
        "%u\n",
        ds->core.inner.a, ds->core.inner.nested.c,
        ds->core.inner.nested.inline_data,
        ds->core.inner.nested.val_union.bitfield_val.bf1,
        ds->core.inner.nested.val_union.bitfield_val.bf2,
        ds->core.inner.nested.val_union.bitfield_val.bf3,
        ds->core.inner.nested.val_union.bitfield_val.bf4,
        ds->core.inner.nested.val_union.bitfield_val.bf5,
        ds->core.inner.nested.val_union.bitfield_val.bf6);
}

void test_combo(ComboStruct* combo) {
    combo->data.i_arr[0] = 10;
    combo->data.i_arr[1] = 0xaa55;

    for (int i = 0; i < combo->count; i++) {
        combo->items[i].id = i;
        combo->items[i].color = (i % 2 == 0) ? RED : GREEN;
        combo->items[i].flags =
            (Flags){.is_enabled = 1, .mode = i, .reserved = 0};
        combo->items[i].data.int_val = i * 100;
        test_item(&combo->items[i]);
    }
}

int main(int argc, char** argv) {
    printf("This program should not be run under any circumstances!\n");
    printf("Its only purpose is to test static binary analysis tools.\n");
    printf("You have 1000s to terminate it now.\n");
    fflush(stdout);
    sleep(1000);

    complicated(atoi(argv[1]));

    volatile Flags f = {.is_enabled = 1, .mode = 3, .reserved = 2};
    test_flags(f);

    volatile ValueUnion vu;
    test_union(vu);

    volatile Item item = {
        .id = 1, .color = BLUE, .flags = f, .data.int_val = 42};
    test_item((Item*)&item);

    volatile DeepStruct ds;
    test_deep_struct((DeepStruct*)&ds);

    ComboStruct* combo = malloc(sizeof(ComboStruct) + 10 * sizeof(Item));
    combo->count = 10;
    test_combo(combo);

    return 0;
}
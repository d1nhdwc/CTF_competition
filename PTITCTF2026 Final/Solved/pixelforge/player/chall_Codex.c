#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

typedef struct Image {
    uint8_t *pixels;     // +0x00
    uint32_t width;      // +0x08
    uint32_t height;     // +0x0c
    uint32_t bpp;        // +0x10: allowed values 1, 3, 4
    uint32_t padding;    // +0x14
    size_t data_len;     // +0x18: width * height * bpp
} Image;

static Image g_images[16];

static const char banner[] =
    "\n  ____  _          _ _____                    \n"
    " |  _ \\(_)_  _____| |  ___|__  _ __ __ _  ___ \n"
    " | |_) | \\ \\/ / _ \\ | |_ / _ \\| '__/ _` |/ _ \\\n"
    " |  __/| |>  <  __/ |  _| (_) | | | (_| |  __/\n"
    " |_|   |_/_/\\_\\___|_|_|  \\___/|_|  \\__, |\\___|\n"
    "                                   |___/      \n";

static const char menu[] =
    "\n1. New image\n"
    "2. Load pixels\n"
    "3. Scale image\n"
    "4. To grayscale\n"
    "5. To rgb\n"
    "6. Brightness\n"
    "7. Image info\n"
    "8. Dump region\n"
    "0. Exit\n"
    ": ";

static void write_str(const char *s) {
    write(1, s, strlen(s));
}

static void write_prompt(void) {
    write(1, ": ", 2);
}

static void write_ok(void) {
    write(1, "ok\n", 3);
}

static void write_err(void) {
    write(1, "err\n", 4);
}

static void read_line_or_exit(char buf[0x30]) {
    memset(buf, 0, 0x30);
    if (read(0, buf, 0x2f) <= 0) {
        exit(0);
    }
}

static uint64_t parse_integer(const char *s, int *is_negative) {
    while (*s == ' ' || *s == '\t') {
        s++;
    }

    int neg = 0;
    if (*s == '+' || *s == '-') {
        neg = (*s == '-');
        s++;
    }

    uint64_t value = 0;
    if (*s == '0' && ((s[1] & 0xdf) == 'X')) {
        s += 2;
        for (;;) {
            unsigned char c = *s;
            unsigned digit;

            if (c >= '0' && c <= '9') {
                digit = c - '0';
            } else if (c >= 'a' && c <= 'f') {
                digit = c - 'a' + 10;
            } else if (c >= 'A' && c <= 'F') {
                digit = c - 'A' + 10;
            } else {
                break;
            }

            value = (value << 4) + digit;
            s++;
        }
    } else {
        while (*s >= '0' && *s <= '9') {
            value = value * 10 + (uint8_t)(*s - '0');
            s++;
        }
    }

    if (is_negative != NULL) {
        *is_negative = neg;
    }
    return value;
}

static void print_uint(uint64_t value) {
    char digits[24];
    char *end = &digits[23];
    *end = '\0';

    do {
        *--end = (char)('0' + (value % 10));
        value /= 10;
    } while (value != 0);

    write(1, end, strlen(end));
}

static Image *prompt_existing_image(void) {
    char line[0x30];

    write_prompt();
    read_line_or_exit(line);
    uint64_t idx = parse_integer(line, NULL);

    if (idx > 15 || g_images[idx].pixels == NULL) {
        write_err();
        return NULL;
    }

    return &g_images[idx];
}

static void load_pixel_triplets(uint8_t *dst, size_t pixel_count, uint32_t bpp) {
    uint8_t input[0x200];
    size_t done = 0;

    while (done < pixel_count) {
        size_t want_pixels = pixel_count - done;
        if (want_pixels > 0x200) {
            want_pixels = 0x200;
        }

        ssize_t nread = read(0, input, want_pixels * 3);
        if (nread <= 2) {
            return;
        }

        size_t got_pixels = (size_t)nread / 3;
        uint8_t *out = dst + done * bpp;
        uint8_t *in = input;

        for (size_t i = 0; i < got_pixels; i++) {
            uint8_t r = in[0];
            uint8_t g = in[1];
            uint8_t b = in[2];

            if (bpp == 1) {
                // Fixed-point grayscale: roughly 0.300*r + 0.589*g + 0.109*b.
                out[0] = (uint8_t)((0x4d * r + 0x97 * g + 0x1c * b) >> 8);
            } else {
                // The binary stores input triplets in B, G, R order.
                out[0] = b;
                out[1] = g;
                out[2] = r;
                if (bpp == 4) {
                    out[3] = 0xff;
                }
            }

            in += 3;
            out += bpp;
        }

        done += got_pixels;
        if ((size_t)nread < want_pixels * 3) {
            return;
        }
    }
}

static int prompt_uint64(uint64_t *out) {
    char line[0x30];

    write_prompt();
    read_line_or_exit(line);
    *out = parse_integer(line, NULL);
    return 1;
}

static int validate_range_1_to(uint64_t value, uint64_t max) {
    return value >= 1 && value <= max;
}

int main(void) {
    char line[0x30];

    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
    alarm(180);

    write_str(banner);

    for (;;) {
        write(1, menu, sizeof(menu) - 1);
        read_line_or_exit(line);

        switch (parse_integer(line, NULL)) {
        case 0:
            write_ok();
            return 0;

        case 1: {
            uint64_t idx, width, height, bpp;

            prompt_uint64(&idx);
            if (idx > 15 || g_images[idx].pixels != NULL) {
                write_err();
                break;
            }

            prompt_uint64(&width);
            prompt_uint64(&height);
            prompt_uint64(&bpp);

            if (!validate_range_1_to(width, 0x1000) ||
                !validate_range_1_to(height, 0x1000) ||
                !(bpp == 1 || bpp == 3 || bpp == 4)) {
                write_err();
                break;
            }

            size_t data_len = width * height * bpp;
            if (data_len > 0x1000) {
                write_err();
                break;
            }

            uint8_t *pixels = malloc(data_len);
            if (pixels == NULL) {
                write_err();
                break;
            }

            g_images[idx].pixels = pixels;
            g_images[idx].width = (uint32_t)width;
            g_images[idx].height = (uint32_t)height;
            g_images[idx].bpp = (uint32_t)bpp;
            g_images[idx].data_len = data_len;
            write_ok();
            break;
        }

        case 2: {
            Image *img = prompt_existing_image();
            if (img == NULL) {
                break;
            }
            if (img->data_len < img->bpp) {
                write_err();
                break;
            }

            write_prompt();
            load_pixel_triplets(img->pixels, img->data_len / img->bpp, img->bpp);
            write_ok();
            break;
        }

        case 3: {
            Image *img = prompt_existing_image();
            uint64_t width_mul, width_div, height_mul, height_div;

            if (img == NULL) {
                break;
            }

            prompt_uint64(&width_mul);
            prompt_uint64(&width_div);
            prompt_uint64(&height_mul);
            prompt_uint64(&height_div);

            if (!validate_range_1_to(width_mul, 0x100000) ||
                !validate_range_1_to(width_div, 0x100000) ||
                !validate_range_1_to(height_mul, 0x100000) ||
                !validate_range_1_to(height_div, 0x100000)) {
                write_err();
                break;
            }

            uint64_t scaled_width_num = (uint64_t)img->width * width_mul;
            uint64_t scaled_height_num = (uint64_t)img->height * height_mul;
            uint64_t new_width = scaled_width_num / width_div;
            uint64_t new_height = scaled_height_num / height_div;

            if (scaled_width_num < width_div ||
                scaled_height_num < height_div ||
                new_width > 0x100000 ||
                new_height > 0x100000) {
                write_err();
                break;
            }

            size_t new_pixel_count = new_width * new_height;

            // Matches the binary: byte count is computed with 32-bit imul and may wrap.
            uint32_t alloc_len32 = (uint32_t)new_height;
            alloc_len32 *= (uint32_t)new_width;
            alloc_len32 *= img->bpp;

            uint8_t *new_pixels = malloc((size_t)alloc_len32);
            if (new_pixels == NULL) {
                write_err();
                break;
            }

            write_prompt();
            load_pixel_triplets(new_pixels, new_pixel_count, img->bpp);

            free(img->pixels);
            img->pixels = new_pixels;
            img->width = (uint32_t)new_width;
            img->height = (uint32_t)new_height;
            img->data_len = (size_t)alloc_len32;
            write_ok();
            break;
        }

        case 4: {
            Image *img = prompt_existing_image();
            if (img == NULL) {
                break;
            }
            if (img->bpp == 1 || img->data_len < img->bpp) {
                write_err();
                break;
            }

            size_t pixel_count = img->data_len / img->bpp;
            uint8_t *gray = malloc(pixel_count);
            if (gray == NULL) {
                write_err();
                break;
            }

            for (size_t i = 0; i < pixel_count; i++) {
                uint8_t *p = img->pixels + i * img->bpp;
                gray[i] = (uint8_t)((p[0] + p[1] + p[2]) / 3);
            }

            free(img->pixels);
            img->pixels = gray;
            img->bpp = 1;
            img->data_len = pixel_count;
            write_ok();
            break;
        }

        case 5: {
            Image *img = prompt_existing_image();
            if (img == NULL) {
                break;
            }
            if (img->bpp != 1 || img->data_len == 0) {
                write_err();
                break;
            }

            size_t new_len = img->data_len * 3;
            if (new_len > 0x8000) {
                write_err();
                break;
            }

            uint8_t *rgb = malloc(new_len);
            if (rgb == NULL) {
                write_err();
                break;
            }

            for (size_t i = 0; i < img->data_len; i++) {
                rgb[3 * i + 0] = img->pixels[i];
                rgb[3 * i + 1] = img->pixels[i];
                rgb[3 * i + 2] = img->pixels[i];
            }

            free(img->pixels);
            img->pixels = rgb;
            img->bpp = 3;
            img->data_len = new_len;
            write_ok();
            break;
        }

        case 6: {
            Image *img = prompt_existing_image();
            int neg = 0;

            if (img == NULL) {
                break;
            }

            write_prompt();
            read_line_or_exit(line);
            int64_t delta = (int64_t)parse_integer(line, &neg);
            if (neg) {
                delta = -delta;
            }

            if (delta < -255 || delta > 255) {
                write_err();
                break;
            }

            for (size_t i = 0; i < img->data_len; i++) {
                int64_t v = (int64_t)img->pixels[i] + delta;
                if (v > 255) {
                    v = 255;
                }
                if (v < 0) {
                    v = 0;
                }
                img->pixels[i] = (uint8_t)v;
            }

            write_ok();
            break;
        }

        case 7: {
            Image *img = prompt_existing_image();
            if (img == NULL) {
                break;
            }

            print_uint(img->width);
            write(1, "x", 1);
            print_uint(img->height);
            write(1, " ", 1);
            print_uint(img->data_len);
            write(1, "\n", 1);
            break;
        }

        case 8: {
            Image *img = prompt_existing_image();
            uint64_t offset, length;

            if (img == NULL) {
                break;
            }
            if (img->data_len == 0) {
                write_err();
                break;
            }

            prompt_uint64(&offset);
            prompt_uint64(&length);

            if (offset >= img->data_len ||
                length == 0 ||
                img->data_len - offset < length) {
                write_err();
                break;
            }

            write(1, img->pixels + offset, length);
            write(1, "\n", 1);
            break;
        }

        default:
            write_err();
            break;
        }
    }
}

#include "sha1.h"

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define rep(i, n) for (int i = 0; i < (n); ++i)

/**
 * Linked list of bytes.
 */
typedef struct Block {
  uint8_t m[64];
  uint8_t len;
  struct Block *next;
} Block;

/**
 * Data to compute SHA1 hash.
 */
struct _Sha1 {
  Block *head;
  uint32_t w[80];
  uint32_t h[5];
};

/**
 * Prototype definitions.
 */
static uint8_t bit_from_left(uint64_t n, uint8_t k);
static uint32_t shift(uint32_t x, uint8_t k);
static uint32_t f(uint32_t t, uint32_t b, uint32_t c, uint32_t d);
static uint32_t k(uint32_t t);

static Block *sha1_tail(Sha1 *sha1);
static uint64_t sha1_sum_len(Sha1 *sha1);

/**
 * Create sha1 instance.
 */
Sha1 *sha1_create() {
  Sha1 *sha1 = (Sha1 *)malloc(sizeof(Sha1));
  sha1->head = NULL;
  sha1->h[0] = 0x67452301;
  sha1->h[1] = 0xEFCDAB89;
  sha1->h[2] = 0x98BADCFE;
  sha1->h[3] = 0x10325476;
  sha1->h[4] = 0xC3D2E1F0;
  return sha1;
}

/**
 * Destroy sha1 instance.
 */
void sha1_destroy(Sha1 *sha1) {
  Block *head = sha1->head;
  while (head) {
    Block *t = head;
    head = head->next;
    free(t);
  }
  free(sha1);
}

/**
 * Append data.
 */
void sha1_append(Sha1 *sha1, const uint8_t *const m, uint8_t len) {
  if (len > 64) {
    fprintf(stderr, "can not append data more than 64 byte.\n");
    exit(1);
  }

  Block *const next = (Block *)malloc(sizeof(Block));
  {
    next->next = NULL;
    next->len = len;
    memset(next->m, 0, sizeof(next->m));
    memcpy(next->m, m, sizeof(uint8_t) * len);
  }

  if (sha1->head == NULL) {
    sha1->head = next;
    return;
  }

  Block *const t = sha1_tail(sha1);
  t->next = next;
}

/**
 * Compute SHA1 hash of appended data.
 */
void sha1_compute(Sha1 *sha1, uint32_t result[5]) {
  if (!sha1->head) {
    fprintf(stderr, "no data is provided.");
    exit(1);
  }

  {  // padding.
    // append 0x80 <length high(4byte)> <length low(4byte)>.
    Block *t = sha1_tail(sha1);
    if (t->len >= 56) {  // append new block for padding.
      for (int i = t->len + 1; i < 64; ++i) {
        t->m[i] = 0x00;
      }
      sha1_append(sha1, (uint8_t *)"", 0);
      if (t->len < 64) {
        t->m[t->len] = 0x80;
      } else {
        t->next->m[0] = 0x80;
      }
      t = t->next;
    } else {
      t->m[t->len] = 0x80;
    }
    const uint64_t len = sha1_sum_len(sha1);
    rep(i, 8) {
      t->m[56 + i] = bit_from_left(len, i);
    }
  }

  Block *bl = sha1->head;
  while (bl) {
    uint8_t *const m = bl->m;
    uint32_t *const w = sha1->w;
    rep(i, 16) {
      w[i] = m[i * 4] << 24;
      w[i] |= m[i * 4 + 1] << 16;
      w[i] |= m[i * 4 + 2] << 8;
      w[i] |= m[i * 4 + 3];
    }

    for (int i = 16; i < 80; ++i) {
      w[i] = shift(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
    }

    uint32_t a[5];
    rep(i, 5) {
      a[i] = sha1->h[i];
    }

    rep(i, 80) {
      const uint32_t temp =
          shift(a[0], 5) + f(i, a[1], a[2], a[3]) + a[4] + w[i] + k(i);
      a[4] = a[3];
      a[3] = a[2];
      a[2] = shift(a[1], 30);
      a[1] = a[0];
      a[0] = temp;
    }

    rep(i, 5) {
      sha1->h[i] += a[i];
    }
    bl = bl->next;
  }

  rep(i, 5) {
    result[i] = sha1->h[i];
  }
}

/**
 * Find tail of sha1's blocks.
 */
static Block *sha1_tail(Sha1 *sha1) {
  Block *b = sha1->head;
  while (b->next) {
    b = b->next;
  }
  return b;
}

/**
 * Sum of sha1's blocks length.
 */
static uint64_t sha1_sum_len(Sha1 *sha1) {
  Block *head = sha1->head;
  uint64_t len = 0;
  while (head) {
    len += head->len;
    head = head->next;
  }
  return len * 8;
}

/**
 * Extract kth bit of n.
 * k originates 0, and 0th means most significat bit.
 */
static uint8_t bit_from_left(uint64_t n, uint8_t k) {
  return (n >> ((7 - k) * 8)) & 0xFF;
}

/**
 * Rotate left shift (x << k).
 */
static uint32_t shift(uint32_t x, uint8_t k) {
  assert(0 <= k && k <= 32);
  return (x << k) | (x >> (32 - k));
}

/**
 * Function f defined by RFC 3174.
 */
static uint32_t f(uint32_t t, uint32_t b, uint32_t c, uint32_t d) {
  assert(0 <= t && t <= 79);
  if (0 <= t && t <= 19) {
    return (b & c) | ((~b) & d);
  }
  if (20 <= t && t <= 39) {
    return b ^ c ^ d;
  }
  if (40 <= t && t <= 59) {
    return (b & c) | (b & d) | (c & d);
  }
  return b ^ c ^ d;
}

/**
 * Function k defined by RFC 3174.
 */
static uint32_t k(uint32_t t) {
  assert(0 <= t && t <= 79);
  if (0 <= t && t <= 19) {
    return 0x5A827999;
  }
  if (20 <= t && t <= 39) {
    return 0x6ED9EBA1;
  }
  if (40 <= t && t <= 59) {
    return 0x8F1BBCDC;
  }
  return 0xCA62C1D6;
}

#ifndef SHA1_H
#define SHA1_H

#include <stdint.h>

typedef struct _Sha1 Sha1;

Sha1 *sha1_create();

void sha1_destroy(Sha1 *sha1);

void sha1_append(Sha1 *sha1, const uint8_t *const m, uint8_t len);

void sha1_compute(Sha1 *sha1, uint32_t result[5]);

#endif

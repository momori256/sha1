#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "sha1.h"

static void print_result(uint32_t result[5]) {
  for (int i = 0; i < 5; ++i) {
    printf("%08x%c", result[i], (i == 4) ? '\n' : ' ');
  }
}

void test() {
  {
    Sha1 *const sha1 = sha1_create();
    const char *const m = "abcde";

    sha1_append(sha1, (uint8_t *)m, strlen(m));

    uint32_t result[5];
    sha1_compute(sha1, result);
    sha1_destroy(sha1);
    print_result(result);

    assert(result[0] == 0x03de6c57);
    assert(result[1] == 0x0bfe24bf);
    assert(result[2] == 0xc328ccd7);
    assert(result[3] == 0xca46b76e);
    assert(result[4] == 0xadaf4334);
  }

  {
    Sha1 *const sha1 = sha1_create();
    const char *const m =
        "0123456789abcdef"
        "0123456789abcdef"
        "0123456789abcdef"
        "0123456789abcdef";

    sha1_append(sha1, (uint8_t *)m, strlen(m));
    sha1_append(sha1, (uint8_t *)m, strlen(m));
    sha1_append(sha1, (uint8_t *)m, strlen(m));

    uint32_t result[5];
    sha1_compute(sha1, result);
    sha1_destroy(sha1);
    print_result(result);

    assert(result[0] == 0xbcade9db);
    assert(result[1] == 0x60c287f0);
    assert(result[2] == 0x249db02e);
    assert(result[3] == 0xfb35cfef);
    assert(result[4] == 0x5b07e54f);
  }
}

int main() {
  test();
  return 0;
}

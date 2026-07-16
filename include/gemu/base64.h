#ifndef BASE64_INCLUDE
#define BASE64_INCLUDE

#include "utils.h"

unsigned char *base64_encode(const unsigned char *src, size_t len, size_t *out_len);


#endif

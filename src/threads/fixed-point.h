#ifndef PINTOS_08_FIXED_POINT_H
#define PINTOS_08_FIXED_POINT_H

#include "lib/stdint.h"

#define FIXED_POINT_CONST_1_OVER_60 273
#define FIXED_POINT_CONST_59_OVER_60 16111
#define FIXED_POINT_CONST_1 16384
#define FIXED_POINT_CONST_2 32768
#define FIXED_POINT_CONST_4 65536
#define FIXED_POINT_CONST_PRI_MAX 1032192
#define FIXED_POINT_CONST_100 1638400

/* Using 64 bit integers to represent a 17-14 fixed-point scheme. */
typedef int64_t int_fp;

#define convert_int_to_fixed_point(X) (X * FIXED_POINT_CONST_1)
#define convert_fixed_point_to_integer_nearest(X) ((X < 0) ? (X - FIXED_POINT_CONST_1 / 2) / FIXED_POINT_CONST_1 : \
                                                  (X > 0) ? (X + FIXED_POINT_CONST_1 / 2) / FIXED_POINT_CONST_1 : X)

#define fixed_point_multiply(X, Y) (X * Y / FIXED_POINT_CONST_1)
#define fixed_point_divide(X, Y) (X * FIXED_POINT_CONST_1 / Y)

#endif //PINTOS_08_FIXED_POINT_H

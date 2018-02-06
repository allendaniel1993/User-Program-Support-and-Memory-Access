#ifndef THREADS_FIXED-POINT_H
#define THREADS_FIXED-POINT_H

#include <debug.h>
#include <stddef.h>
#include <random.h>
#include <stdio.h>
#include <string.h>

int covert_to_fixed(int);
int convert_to_r_int(int);
int mul_fixed(int, int);
int div_fixed(int, int);
int add_int(int, int);
int sub_int(int, int);
int sub_fixed(int, int);
int add_fixed(int, int);
int div_int(int,int);
int mul_int(int, int);
int convert_to_int(int);

#endif /* threads/fixed-point.h */


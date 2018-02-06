#include "threads/fixed-point.h"
#include <debug.h>
#include <stddef.h>
#include <random.h>
#include <stdio.h>
#include <string.h>

static int f = 1<<14;

/* Convert integer to fixed-point */

int
convert_to_fixed(int n)
{
	            return (n * f); 
}

/* Convert fixed point to integer - rounded */

int
convert_to_r_int(int x)
{
	        if(x >= 0)
				 return (((x) + (f / 2)) / f );
			 else
				return (((x) - (f / 2)) / f); 
}

/* Multiply two fixed  point numbers */
int 
mul_fixed(int x,int y)
{
	            return (((int64_t)x) * y / f); 
}

/* Divide two fixed numbers */
int 
div_fixed(int x,int y)
{
	            return ((((int64_t)(x)) * f) / y); 
}

/* Add fixed pont number and integer */
int 
add_int(int x, int n)
{
	      return (x + (n) * f); 
}

/* Subtract fixed number and integer */
int 
sub_int(int x, int n)
{
	      return (x - (n) * f); 
}

/* Subtrct two fixed points */
int 
sub_fixed(int x, int y)
{
	      return (x-y);
}

/* Add two fixed points */
int 
add_fixed(int x, int y)
{
	        return(x+y);
}

/* Multiply fixed point adn intege */
int 
mul_int(int x,int n)
{
	        return (x*n);
}

/* Divide fixed point and integer */
int 
div_int(int x, int n)
{
	        return (x/n);
}

/* Convert fixed to integer - without rounding */
int 
convert_to_int(int x)
{
		return (x/f);
}


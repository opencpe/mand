#ifndef __DM_ASSERT_H
#define __DM_ASSERT_H

#include "compiler.h"

#if defined(NDEBUG)
#define dm_assert(expr) do { } while (0)
#else

/* This prints an "Assertion failed" message and aborts.  */
void __dm_assert_fail (const char *assertion, unsigned int line, const char *function)
	__attribute__ ((__noreturn__));
void __dm_type_assert_fail(const char *expected, int got, unsigned int line, const char *function)
	__attribute__ ((__noreturn__));
void __dm_parity_assert_fail(unsigned int expected, unsigned int got, unsigned int line, const char *function)
	__attribute__ ((__noreturn__));
void __dm_magic_assert_fail(const char *field, const void *ptr, unsigned int expected, unsigned int got, unsigned int line, const char *function)
	__attribute__ ((__noreturn__));

#define dm_assert(expr)							\
	do {								\
		if (unlikely(!(expr)))					\
			__dm_assert_fail(#expr, __LINE__, __FUNCTION__); \
	} while (0)

#define dm_assert_magic(ptr, left, right)				\
	do {								\
		if (unlikely((left) != (right)))			\
			__dm_magic_assert_fail(#left, ptr, right, left, __LINE__, __FUNCTION__); \
	} while (0)

#endif

#endif

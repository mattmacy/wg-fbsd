#ifndef SYS_SUPPORT_H_
#define SYS_SUPPORT_H_

#include <sys/types.h>
#include <sys/limits.h>
#include <sys/endian.h>
#include <sys/libkern.h>
#include <sys/malloc.h>

#define COMPAT_ZINC_IS_A_MODULE
MALLOC_DECLARE(M_WG);

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint32_t __le32;
typedef uint64_t  u64;
typedef uint64_t  __le64;

#define get_unaligned_le32(x) le32dec(x)
#define get_unaligned_le64(x) le64dec(x)

#define cpu_to_le64(x) htole64(x)
#define cpu_to_le32(x) htole32(x)

static inline void
put_unaligned_le32(u32 val, void *p)
{
	*((__le32 *)p) = cpu_to_le32(val);
}


#define rol32(i32, n) ((i32) << (n) | (i32) >> (32 - (n)))

#define memzero_explicit(p, s) explicit_bzero(p, s)

#define EXPORT_SYMBOL(x)

#define U32_MAX		((u32)~0U)
#define DONT_USE_SIMD ((simd_context_t []){ })

typedef struct simd_context {} simd_context_t;

#define simd_get(x)
#define simd_put(x)
#define simd_relax(x)
#define unlikely(x) __predict_false(x)
#define likely(x) __predict_true(x)
/* Generic path for arbitrary size */


static inline unsigned long
__crypto_memneq_generic(const void *a, const void *b, size_t size)
{
	unsigned long neq = 0;

	while (size >= sizeof(unsigned long)) {
		neq |= *(const unsigned long *)a ^ *(const unsigned long *)b;
		__compiler_membar();
		a  = ((const char *)a + sizeof(unsigned long));
		b = ((const char *)b + sizeof(unsigned long));
		size -= sizeof(unsigned long);
	}
	while (size > 0) {
		neq |= *(const unsigned char *)a ^ *(const unsigned char *)b;
		__compiler_membar();
		a  = (const char *)a + 1;
		b = (const char *)b + 1;
		size -= 1;
	}
	return neq;
}

#define crypto_memneq(a, b, c) __crypto_memneq_generic((a), (b), (c))

static inline void
__cpu_to_le32s(uint32_t *buf)
{
	*buf = htole32(buf);
}

static inline void cpu_to_le32_array(u32 *buf, unsigned int words)
{
	while (words--) {
		__cpu_to_le32s(buf);
		buf++;
	}
}

#define CONFIG_HAVE_EFFICIENT_UNALIGNED_ACCESS 1
void __crypto_xor(u8 *dst, const u8 *src1, const u8 *src2, unsigned int len);

static inline void crypto_xor_cpy(u8 *dst, const u8 *src1, const u8 *src2,
				  unsigned int size)
{
	if (CONFIG_HAVE_EFFICIENT_UNALIGNED_ACCESS &&
	    __builtin_constant_p(size) &&
	    (size % sizeof(unsigned long)) == 0) {
		unsigned long *d = (unsigned long *)dst;
		const unsigned long *s1 = (const unsigned long *)src1;
		const unsigned long *s2 = (const unsigned long *)src2;

		while (size > 0) {
			*d++ = *s1++ ^ *s2++;
			size -= sizeof(unsigned long);
		}
	} else {
		__crypto_xor(dst, src1, src2, size);
	}
}
#include <sys/kernel.h>
#define	module_init(fn)							\
static void \
wrap_ ## fn(void *dummy __unused) \
{								 \
	fn();						 \
}																		\
SYSINIT(zfs_ ## fn, SI_SUB_LAST, SI_ORDER_FIRST, wrap_ ## fn, NULL)


#define	module_exit(fn) 							\
static void \
wrap_ ## fn(void *dummy __unused) \
{								 \
	fn();						 \
}																		\
SYSUNINIT(zfs_ ## fn, SI_SUB_LAST, SI_ORDER_FIRST, wrap_ ## fn, NULL)

#define module_param(a, b, c)
#define MODULE_LICENSE(x)
#define MODULE_DESCRIPTION(x)
#define MODULE_AUTHOR(x)

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

#define __initconst
#define __initdata
#define __init
#define __exit
#define BUG() panic("%s:%d bug hit!\n", __FILE__, __LINE__)
#define pr_err printf
#define IS_ENABLED(x) 0
#define kmalloc(size, flag) malloc((size), M_WG, M_WAITOK)
#define kfree(p) free(p, M_WG)
#define vzalloc(size) malloc((size), M_WG, M_WAITOK|M_ZERO)
#define vfree(p) free(p, M_WG)
#endif

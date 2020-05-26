#ifndef SYS_SUPPORT_H_
#define SYS_SUPPORT_H_
#ifndef __LOCORE
#include <sys/types.h>
#include <sys/limits.h>
#include <sys/endian.h>
#include <sys/libkern.h>
#include <sys/malloc.h>
#include <sys/proc.h>
#include <sys/lock.h>
#include <vm/uma.h>

#include <machine/fpu.h>

#include <crypto/siphash/siphash.h>


#define COMPAT_ZINC_IS_A_MODULE
MALLOC_DECLARE(M_WG);

#define	BUILD_BUG_ON(x)			CTASSERT(!(x))

#define BIT(nr)                 (1UL << (nr))
#define BIT_ULL(nr)             (1ULL << (nr))
#ifdef __LP64__
#define BITS_PER_LONG           64
#else
#define BITS_PER_LONG           32
#endif

#define rw_enter_write rw_wlock
#define rw_exit_write rw_wunlock
#define rw_enter_read rw_rlock
#define rw_exit_read rw_runlock
#define rw_exit rw_unlock

#define ASSERT(x) MPASS(x)

#define ___PASTE(a,b) a##b
#define __PASTE(a,b) ___PASTE(a,b)
#define __UNIQUE_ID(prefix) __PASTE(__PASTE(__UNIQUE_ID_, prefix), __COUNTER__)

#define typeof(x) __typeof__(x)

#define __typecheck(x, y) \
		(!!(sizeof((typeof(x) *)1 == (typeof(y) *)1)))

/*
 * This returns a constant expression while determining if an argument is
 * a constant expression, most importantly without evaluating the argument.
 * Glory to Martin Uecker <Martin.Uecker@med.uni-goettingen.de>
 */
#define __is_constexpr(x) \
	(sizeof(int) == sizeof(*(8 ? ((void *)((long)(x) * 0l)) : (int *)8)))

#define __no_side_effects(x, y) \
		(__is_constexpr(x) && __is_constexpr(y))

#define __safe_cmp(x, y) \
		(__typecheck(x, y) && __no_side_effects(x, y))

#define __cmp(x, y, op)	((x) op (y) ? (x) : (y))

#define __cmp_once(x, y, unique_x, unique_y, op) ({	\
		typeof(x) unique_x = (x);		\
		typeof(y) unique_y = (y);		\
		__cmp(unique_x, unique_y, op); })

#define __careful_cmp(x, y, op) \
	__builtin_choose_expr(__safe_cmp(x, y), \
		__cmp(x, y, op), \
		__cmp_once(x, y, __UNIQUE_ID(__x), __UNIQUE_ID(__y), op))

#define min_t(type, x, y)	__careful_cmp((type)(x), (type)(y), <)

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint32_t __le32;
typedef uint64_t  u64;
typedef uint64_t  __le64;

#define __must_check		__attribute__((__warn_unused_result__))
#define asmlinkage
#define __ro_after_init

#define get_unaligned_le32(x) le32dec(x)
#define get_unaligned_le64(x) le64dec(x)

#define cpu_to_le64(x) htole64(x)
#define cpu_to_le32(x) htole32(x)
#define letoh64(x) le64toh(x)

#define	need_resched() (curthread->td_flags & (TDF_NEEDRESCHED|TDF_ASTPENDING))

#define CONTAINER_OF(a, b, c) __containerof((a), b, c)

typedef struct {
	uint64_t	k0;
	uint64_t	k1;
} SIPHASH_KEY;

static inline uint64_t
siphash24(const SIPHASH_KEY *key, const void *src, size_t len)
{
	SIPHASH_CTX ctx;

	return (SipHashX(&ctx, 2, 4, (const uint8_t *)key, src, len));
}

static inline void
put_unaligned_le32(u32 val, void *p)
{
	*((__le32 *)p) = cpu_to_le32(val);
}


#define rol32(i32, n) ((i32) << (n) | (i32) >> (32 - (n)))

#define memzero_explicit(p, s) explicit_bzero(p, s)

#define EXPORT_SYMBOL(x)

#define U32_MAX		((u32)~0U)

#define	kfpu_begin() {							\
	critical_enter();					\
	fpu_kern_enter(curthread, NULL, FPU_KERN_NOCTX); \
}

#define	kfpu_end()	 {						 \
		fpu_kern_leave(curthread, NULL); \
		critical_exit();			     \
}

typedef enum {
	HAVE_NO_SIMD = 1 << 0,
	HAVE_FULL_SIMD = 1 << 1,
	HAVE_SIMD_IN_USE = 1 << 31
} simd_context_t;

#define DONT_USE_SIMD ((simd_context_t []){ HAVE_NO_SIMD })

static __must_check inline bool
may_use_simd(void)
{
#if defined(__amd64__)
	return true;
#else
	return false;
#endif
}

static inline void
simd_get(simd_context_t *ctx)
{
	*ctx = may_use_simd() ? HAVE_FULL_SIMD : HAVE_NO_SIMD;
}

static inline void
simd_put(simd_context_t *ctx)
{
	if (*ctx & HAVE_SIMD_IN_USE)
		kfpu_end();
	*ctx = HAVE_NO_SIMD;
}

static __must_check inline bool
simd_use(simd_context_t *ctx)
{
	if (!(*ctx & HAVE_FULL_SIMD))
		return false;
	if (*ctx & HAVE_SIMD_IN_USE)
		return true;
	kfpu_begin();
	*ctx |= HAVE_SIMD_IN_USE;
	return true;
}

static inline bool
simd_relax(simd_context_t *ctx)
{
	if ((*ctx & HAVE_SIMD_IN_USE) && need_resched()) {
		simd_put(ctx);
		simd_get(ctx);
		return true;
	}
	return false;
}

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
	*buf = htole32(*buf);
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

#define	WARN_ON(cond) ({					\
      bool __ret = (cond);					\
      if (__ret) {						\
		printf("WARNING %s failed at %s:%d\n",		\
		    __stringify(cond), __FILE__, __LINE__);	\
      }								\
      unlikely(__ret);						\
})

#define pr_err printf
#define pr_info printf
#define IS_ENABLED(x) 0
#define	___stringify(...)		#__VA_ARGS__
#define	__stringify(...)		___stringify(__VA_ARGS__)
#define kmalloc(size, flag) malloc((size), M_WG, M_WAITOK)
#define kfree(p) free(p, M_WG)
#define vzalloc(size) malloc((size), M_WG, M_WAITOK|M_ZERO)
#define vfree(p) free(p, M_WG)
#endif
#endif

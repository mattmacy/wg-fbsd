#ifndef SYS_SUPPORT_H_
#define SYS_SUPPORT_H_

#include <sys/types.h>
#include <sys/limits.h>
#include <sys/endian.h>
#include <sys/libkern.h>


typedef uint32_t u32;
typedef uint64_t  __le64;
typedef uint64_t  u64;

#define get_unaligned_le32(x) le32dec(x)

#define cpu_to_le64(x) htole64(x)

#define memzero_explicit(p, s) explicit_bzero(p, s)

#define EXPORT_SYMBOL(x)

#endif

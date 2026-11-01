/*
 * Minimal C shim over Valgrind's client-request protocol.
 *
 * The protocol is a platform-specific inline-assembly sequence. Including
 * Valgrind's own headers lets Valgrind emit it, so we never hand-maintain
 * per-architecture assembly in Rust. These three functions are the entire
 * native surface of this crate.
 *
 * Outside Valgrind every client request is a no-op and RUNNING_ON_VALGRIND is
 * zero, so a binary built against this shim runs normally and uninstrumented.
 */
#include <valgrind/memcheck.h>
#include <valgrind/valgrind.h>
#include <stddef.h>

/* Mark bytes as undefined in the shadow state. The real values are untouched. */
void trace_check_mark_undefined(void *addr, size_t len) {
    VALGRIND_MAKE_MEM_UNDEFINED(addr, len);
}

/* Restore definedness, declassifying the bytes for ordinary use. */
void trace_check_mark_defined(void *addr, size_t len) {
    VALGRIND_MAKE_MEM_DEFINED(addr, len);
}

/* Non-zero only when running under a Valgrind tool. */
int trace_check_running_on_valgrind(void) {
    return RUNNING_ON_VALGRIND != 0;
}

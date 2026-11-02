//! Freestanding verification targets for BINSEC relational symbolic execution.
//!
//! `no_std` with no libc, built as a small static ELF. There is no runtime to
//! symbolically execute, which is what keeps analysis focused on the primitive
//! under test rather than on program startup.
//!
//! Inputs are `#[no_mangle] pub static mut` globals because BINSEC's script
//! language declares secrets and publics by **symbol name**
//! (`secret global TC_SECRET`). Each case starts at a `tc_harness_*` symbol and
//! halts at `tc_halt`, so `_start` is never explored.
//!
//! Every target is `#[inline(never)]` so it survives as a distinct function
//! with a stable address, and reads go through `read_volatile` so the optimizer
//! cannot fold the globals away.

#![no_std]
#![no_main]

/// The modeled secret.
#[no_mangle]
pub static mut TC_SECRET: u8 = 0;

/// A public input. Used as a mode selector and as a loop bound.
#[no_mangle]
pub static mut TC_PUBLIC: u8 = 0;

/// A public lookup table.
#[no_mangle]
pub static mut TC_TABLE: [u8; 16] = [0; 16];

/// Where harnesses write their result, so it cannot be optimized away.
#[no_mangle]
pub static mut TC_OUT: u8 = 0;

// ---------------------------------------------------------------------------
// Targets
// ---------------------------------------------------------------------------

/// Vulnerable: the secret selects a load address.
///
/// Compiles to `and $0xf,%esi; movzbl (%rdi,%rsi,1),%eax` — the instruction
/// sequence is identical for every secret, so only an address-aware analysis
/// can see this. M1's instruction-path comparison cannot.
#[inline(never)]
#[no_mangle]
pub extern "C" fn secret_lookup(table: *const u8, secret: u8) -> u8 {
    unsafe { core::ptr::read_volatile(table.add((secret & 15) as usize)) }
}

/// Constant-time: reads every entry and selects with a mask.
#[inline(never)]
#[no_mangle]
pub extern "C" fn masked_scan(table: *const u8, secret: u8) -> u8 {
    let want = secret & 15;
    let mut acc = 0u8;
    let mut i = 0u8;
    while i < 16 {
        // 0xff when i == want, 0x00 otherwise, computed without branching.
        let hit = ((((i ^ want) as i16) - 1) >> 15) as u8;
        acc |= unsafe { core::ptr::read_volatile(table.add(i as usize)) } & hit;
        i += 1;
    }
    acc
}

/// Vulnerable: the secret determines a loop's trip count.
///
/// This is the branch example that survives optimization. A secret-dependent
/// `if` returning constants gets if-converted into arithmetic — verified, see
/// [`erased_branch`] — but a loop's backward conditional jump cannot be.
/// Masked to three bits so exhaustive exploration stays cheap.
#[inline(never)]
#[no_mangle]
pub extern "C" fn secret_trip_count(table: *const u8, secret: u8) -> u8 {
    let bound = secret & 7;
    let mut acc = 0u8;
    let mut i = 0u8;
    while i < bound {
        acc = acc.wrapping_add(unsafe { core::ptr::read_volatile(table.add(0)) });
        i = i.wrapping_add(1);
    }
    acc
}

/// A source-level secret branch that the compiler removes.
///
/// Kept deliberately. At `-O` this becomes `shr $0x7` plus `sub` with **zero**
/// conditional jumps, so the honest verdict is that the compiled code has no
/// secret-dependent control flow. Its declared expectation is therefore
/// `VERIFIED_BOUNDED`, not a manufactured leak — the fourth instance of
/// compiler branch-erasure recorded in this project.
#[inline(never)]
#[no_mangle]
pub extern "C" fn erased_branch(sink: *mut u8, secret: u8) -> u8 {
    unsafe {
        if core::ptr::read_volatile(&secret) > 0x7f {
            core::ptr::write_volatile(sink, 1);
            1
        } else {
            core::ptr::write_volatile(sink, 2);
            0
        }
    }
}

/// Branches on a **public** input only. Must not be reported as a secret leak,
/// because both compared executions share the same public value.
#[inline(never)]
#[no_mangle]
pub extern "C" fn public_branch(table: *const u8, public: u8, secret: u8) -> u8 {
    let base = if (public & 1) == 0 { 0usize } else { 8usize };
    // The secret is consumed by arithmetic only, never by an address or branch.
    let mixed = secret.wrapping_mul(3).rotate_left(2);
    unsafe { core::ptr::read_volatile(table.add(base)) ^ mixed }
}

/// The milestone's key demonstration: a leak reachable only under one public
/// mode.
///
/// A dynamic test exercising `public == 0` observes nothing, because that path
/// is the masked scan. The vulnerable path requires `public != 0`, which only a
/// search over the public domain will visit.
#[inline(never)]
#[no_mangle]
pub extern "C" fn conditional_lookup(table: *const u8, public: u8, secret: u8) -> u8 {
    if public == 0 {
        masked_scan(table, secret)
    } else {
        secret_lookup(table, secret)
    }
}

/// A loop whose trip count depends on a **public** input, used to drive
/// exploration past a deliberately small depth bound.
#[inline(never)]
#[no_mangle]
pub extern "C" fn public_loop(table: *const u8, public: u8) -> u8 {
    let mut acc = 0u8;
    let mut i = 0u8;
    while i < public {
        acc = acc.wrapping_add(unsafe { core::ptr::read_volatile(table.add((i & 15) as usize)) });
        i = i.wrapping_add(1);
    }
    acc
}

// ---------------------------------------------------------------------------
// Harnesses: one entry symbol per verification case
// ---------------------------------------------------------------------------

/// Where every harness halts. BINSEC stops here, so nothing beyond the target
/// is explored.
#[inline(never)]
#[no_mangle]
pub extern "C" fn tc_halt() -> ! {
    unsafe {
        core::ptr::read_volatile(&raw const TC_OUT);
    }
    loop {}
}

macro_rules! harness {
    ($name:ident => $body:expr) => {
        #[inline(never)]
        #[no_mangle]
        pub extern "C" fn $name() -> ! {
            let out: u8 = $body;
            unsafe { core::ptr::write_volatile(&raw mut TC_OUT, out) };
            tc_halt()
        }
    };
}

/// Reads the declared globals. Volatile so the values genuinely come from the
/// memory BINSEC made symbolic.
#[inline(always)]
fn inputs() -> (*const u8, u8, u8) {
    unsafe {
        (
            (&raw const TC_TABLE).cast(),
            core::ptr::read_volatile(&raw const TC_PUBLIC),
            core::ptr::read_volatile(&raw const TC_SECRET),
        )
    }
}

harness!(tc_harness_table_lookup => {
    let (table, _public, secret) = inputs();
    secret_lookup(table, secret)
});

harness!(tc_harness_masked_scan => {
    let (table, _public, secret) = inputs();
    masked_scan(table, secret)
});

harness!(tc_harness_trip_count => {
    let (table, _public, secret) = inputs();
    secret_trip_count(table, secret)
});

harness!(tc_harness_erased_branch => {
    let (_table, _public, secret) = inputs();
    erased_branch(&raw mut TC_OUT, secret)
});

harness!(tc_harness_public_branch => {
    let (table, public, secret) = inputs();
    public_branch(table, public, secret)
});

harness!(tc_harness_conditional_lookup => {
    let (table, public, secret) = inputs();
    conditional_lookup(table, public, secret)
});

harness!(tc_harness_public_loop => {
    let (table, public, _secret) = inputs();
    public_loop(table, public)
});

/// Keeps every harness reachable so none is dropped as dead code. BINSEC starts
/// at a harness symbol directly, so this dispatch is never explored.
#[no_mangle]
pub extern "C" fn _start() -> ! {
    match unsafe { core::ptr::read_volatile(&raw const TC_PUBLIC) } {
        0 => tc_harness_table_lookup(),
        1 => tc_harness_masked_scan(),
        2 => tc_harness_trip_count(),
        3 => tc_harness_erased_branch(),
        4 => tc_harness_public_branch(),
        5 => tc_harness_conditional_lookup(),
        _ => tc_harness_public_loop(),
    }
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}

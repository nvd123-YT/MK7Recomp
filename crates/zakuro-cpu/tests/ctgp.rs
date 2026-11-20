//! Regression test for the 3GX executable decrypt/check routine embedded by
//! the CTGP-7 plugin loader. This exercises the exact ARM instruction sequence
//! that decrypts the three plugin sections and computes the header checksum.

mod common;

use common::{assert_reg, run_with, CODE_BASE, DATA_BASE};
use zakuro_cpu::Exit;

#[test]
fn ctgp_3gx_executable_check_decrypts_and_returns_the_expected_checksum() {
    // The first word is chosen so the first ROR-by-register uses a shift of
    // zero. The remaining words cover changing shift counts and wrapping math.
    let Some(run) = run_with(
        "
            push {r6-r11, lr}
            ldr r8, [r2]
            ldr r9, [r2, #4]
            ldr r10, [r2, #8]
            mov r7, #0
        loop:
            ldr r6, [r0]
            eor r6, r6, r8
            mul r11, r9, r10
            add r6, r6, r11
            str r6, [r0], #4
            add r11, r6, #1
            and r11, r11, #15
            ror r8, r8, r11
            mul r8, r8, r10
            add r9, r9, r6
            add r10, r10, #91
            add r7, r7, r6
            cmp r0, r1
            bne loop
            mov r0, r7
            pop {r6-r11, pc}
        ",
        |cpu, bus| {
            let input = [
                0x94D2_35A3,
                0x1234_5678,
                0xCAFE_BABE,
                0x0BAD_F00D,
            ];
            let args = [0x78C8_0FC9, 0xCEA7_E683, 0xC93E_1F87, 0];

            for (i, word) in input.iter().enumerate() {
                bus.write_bytes(DATA_BASE + (i as u32 * 4), &word.to_le_bytes());
            }
            for (i, word) in args.iter().enumerate() {
                bus.write_bytes(DATA_BASE + 0x100 + (i as u32 * 4), &word.to_le_bytes());
            }

            cpu.regs[0] = DATA_BASE;
            cpu.regs[1] = DATA_BASE + (input.len() as u32 * 4);
            cpu.regs[2] = DATA_BASE + 0x100;
            // The helper appends BKPT immediately after the 21 ARM words.
            cpu.regs[14] = CODE_BASE + 21 * 4;
        },
    ) else {
        return;
    };

    assert!(matches!(&run.exit, Exit::Breakpoint { .. }));
    assert_reg!(run, 0, 0x352C_EAAF);
    assert_eq!(run.bus.read_u32(DATA_BASE), 0xEA48_A67F);
    assert_eq!(run.bus.read_u32(DATA_BASE + 4), 0xBB0F_B94B);
    assert_eq!(run.bus.read_u32(DATA_BASE + 8), 0x96F0_A963);
    assert_eq!(run.bus.read_u32(DATA_BASE + 12), 0xF8E3_E182);
}

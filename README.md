![](repo/ipwndfu.png)
# Open-source jailbreaking tool for older iOS devices


**Read [disclaimer](#disclaimer) before using this software.*


## Features

* Jailbreak and downgrade iPhone 3GS (new bootrom) with alloc8 untethered bootrom exploit. :-)

* Pwned DFU Mode exploit for S5L8920 devices using limera1n exploit.

* Dump SecureROM on S5L8920 devices.

* Dump NOR on S5L8920 devices.

* Flash NOR on S5L8920 devices.

* Encrypt or decrypt hex data on a connected device in pwned DFU Mode using its GID or UID key.


## Dependencies

This tool should be compatible with Mac and Linux. It won't work in a virtual machine.

* libusb, `brew install libusb`
* [iPhone 3GS iOS 4.3.5 iBSS](#ibss)
* [libusb patch for El Capitan and Sierra](#patch)

## Patch
**Only applicable to El Capitan and Sierra.**

Technical explanation for USB issues in El Capitan and Sierra:

https://www.belle-aurore.com/mike/2016/06/os-x-el-capitan-and-its-refusal-to-reset-usb-devices/

You should have libusb installed using brew. Make sure you are using 1.0.21 (latest version as of writing).

Calculate the SHA1 hash:

```
openssl sha1 /usr/local/Cellar/libusb/1.0.21/lib/libusb-1.0.0.dylib
```

Currently supported hashes (original -> patched):
```
libusb 1.0.21 on macOS Sierra
02da61201c8f67b723bca5fb44b35797d1021625 -> f356ee6052cd520b46ca50333b937ff2efe4477b
```

Available patches are in libusb-patches folder. Apply the patch matching your SHA1 hash using bspatch:

```
sudo bspatch /usr/local/Cellar/libusb/1.0.21/lib/libusb-1.0.0.dylib /usr/local/Cellar/libusb/1.0.21/lib/libusb-1.0.0.dylib libusb-1.0.21-02da61201c8f67b723bca5fb44b35797d1021625.patch
```




## Tutorial

This tool can be used to downgrade or jailbreak iPhone 3GS (new bootrom) without SHSH blobs, as documented in [JAILBREAK-GUIDE](https://github.com/axi0mX/ipwndfu/blob/master/JAILBREAK-GUIDE.md).



## Exploit write-up

Write-up for alloc8 exploit can be found here:

https://github.com/axi0mX/alloc8


## iBSS

Download iPhone 3GS iOS 4.3.5 IPSW from Apple:

http://appldnld.apple.com/iPhone4/041-1965.20110721.gxUB5/iPhone2,1_4.3.5_8L1_Restore.ipsw

In Terminal, extract iBSS using the following command, then move the file to ipwndfu folder:

```
unzip -p iPhone2,1_4.3.5_8L1_Restore.ipsw Firmware/dfu/iBSS.n88ap.RELEASE.dfu > n88ap-iBSS-4.3.5.img3
```


## Coming soon!

* Reorganize and refactor code.

* Easier setup: remove requirement to patch libusb, download iBSS automatically using partial zip.

* Pwned DFU Mode exploit for S5L8720/S5L8922/S5L8930 devices compatible with Yosemite, El Capitan, and Sierra.

* Dump SecureROM on S5L8720/S5L8922/S5L8930 devices.

* Install custom boot logos on devices jailbroken with 24Kpwn and alloc8.

* Enable verbose boot on devices jailbroken with 24Kpwn and alloc8.

## Disclaimer

**This is BETA software.**

Backup your data.

This tool is currently in beta and could potentially brick your device. It will attempt to save a copy of data in NOR to nor-backups folder before flashing new data to NOR, and it will attempt to not overwrite critical data in NOR which your device requires to function. If something goes wrong, hopefully you will be able to restore to latest IPSW in iTunes and bring your device back to life, or use nor-backups to restore NOR to the original state, but I cannot provide any guarantees.

**There is NO warranty provided.**

THERE IS NO WARRANTY FOR THE PROGRAM, TO THE EXTENT PERMITTED BY APPLICABLE LAW. THE ENTIRE RISK AS TO THE QUALITY AND PERFORMANCE OF THE PROGRAM IS WITH YOU. SHOULD THE PROGRAM PROVE DEFECTIVE, YOU ASSUME THE COST OF ALL NECESSARY SERVICING, REPAIR OR CORRECTION.

## Credit

geohot for limera1n exploit

walac for pyusb

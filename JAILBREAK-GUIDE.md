# Jailbreak guide for iPhone 3GS (new bootrom)

### Steps

* Backup your data.

* Create a custom 24Kpwn IPSW for iPhone 3GS (old bootrom).

* Restore to this custom IPSW on your iPhone 3GS (new bootrom).

* After restore is complete, your phone will connect back to your computer in DFU Mode. The screen will be black. This is expected. 24Kpwn exploit does not work on iPhone 3GS (new bootrom).

* Use ipwndfu to put your device into pwned DFU Mode:

```
$ ./ipwndfu -p
*** based on limera1n exploit (heap overflow) by geohot ***
Found: CPID:8920 CPRV:15 CPFM:03 SCEP:03 BDID:00 ECID:XXXXXXXXXXXXXXXX SRTG:[iBoot-359.3.2]
Device is now in pwned DFU Mode.
```

* Once in pwned DFU Mode, use the -x flag to install the alloc8 exploit. This step will replace 24Kpwn exploit with alloc8.

```
$ ./ipwndfu -x
Installing alloc8 exploit to NOR.
Dumping NOR, part 1/8.
Dumping NOR, part 2/8.
Dumping NOR, part 3/8.
Dumping NOR, part 4/8.
Dumping NOR, part 5/8.
Dumping NOR, part 6/8.
Dumping NOR, part 7/8.
Dumping NOR, part 8/8.
NOR backed up to file: nor-backups/nor-XXXXXXXXXXXXXXXX-20170409-224258.dump
Sending iBSS.
Waiting for iBSS to enter Recovery Mode.
Sending iBSS payload to flash NOR.
Sending run command.
If screen is not red, NOR was flashed succcesfully and device will reboot.
```

* Installation takes about 30 seconds. Once NOR is being flashed, the screen will be green for about 10 seconds, and then your phone will reboot.

* If there are any errors before the screen turned green, it is safe to try again.

* If the screen turns red, something went wrong while your phone was being flashed. Trying again probably won't help.

* If there are no issues, the phone will reboot and automatically boot into iOS.


### 3-second delays when using a phone jailbroken with alloc8

alloc8 delays boot in the bootrom by about 3 seconds.

When your phone is off, to turn it on you will need to keep holding the Power button for at least 3 seconds, or your phone will not turn on. This might be because LLB protects against accidental presses of the Power button by shutting down the phone if the power button is not being held anymore. Without an exploit it takes less than a second before this check happens, but with alloc8 exploit it will happen after about 3 seconds. It might be possible to change this behavior by patching LLB.

If your phone enters deep sleep, there will be a 3 second delay before it wakes up. This can be fixed if you disable deep sleep with a tweak from Cydia, but your phone's battery life will decrease.


### Where to download older IPSWs

Always download IPSWs directly from Apple, because IPSWs from other sites could be infected with malware.

There is a trusted site where you can find legitimate Apple download links for older IPSW files:

https://ipsw.me/


### How to create a 24Kpwn IPSW

Older versions of PwnageTool can be found here: https://github.com/axi0mX/PwnageTool-mirror

#### PwnageTool 3.1.3

iOS 3.1 (tested and worked)


#### PwnageTool 3.1.5

iOS 3.1.2 (tested and worked)

iOS 3.1.3 (tested and worked)


#### PwnageTool 4.01

iOS 4.0 (tested and worked)


#### redsn0w 0.9.15b3

```
Q: 'Will this custom IPSW be used on a newer (fixed) version of the iPhone3GS?' 
A:  No [You must answer No to create a 24Kpwn IPSW using redsn0w]
```

iOS 4.3.3 (tested and worked)

iOS 5.0 (failed to restore)

iOS 5.0.1 (tested and worked)

iOS 5.1 (tested and worked)

iOS 5.1.1 (tested and worked)


### How to restore to a custom IPSW

* All versions of iTunes before 11.1 can be used to restore to a custom IPSW in pwned DFU Mode. You can download and install an old version of iTunes in a Windows virtual machine or use a very old Mac with an old version of iTunes. You can use any compatible tool to enter pwned DFU, but it probably won't work in a virtual machine. On a Mac, you can run ipwndfu -p in Terminal and then restore a custom IPSW in iTunes in a virtual machine.

* Use idevicerestore from libimobiledevice. Because of limera1n exploit issues, this might not work in a virtual machine or on a Mac.
```
idevicerestore -c -e your_custom_IPSW.ipsw
```

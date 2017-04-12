# Jailbreak guide for iPhone 3GS (new bootrom)

### Steps

1. Backup your data. Everything will be removed from your phone as it is a **full** restore.

2. [Generate a custom 24Kpwn IPSW for iPhone 3GS (old bootrom)](#how-to-create-a-24kpwn-ipsw).

3. [Restore to this custom IPSW on your iPhone 3GS (new bootrom)](#how-to-restore-to-a-custom-ipsw).

4. After restore is complete, your phone will connect back to your computer in DFU Mode. The screen will be black. This is expected. 24Kpwn exploit does not work on iPhone 3GS (new bootrom).

5. Use ipwndfu to put your device into pwned DFU Mode:

```
$ ./ipwndfu -p
*** based on limera1n exploit (heap overflow) by geohot ***
Found: CPID:8920 CPRV:15 CPFM:03 SCEP:03 BDID:00 ECID:XXXXXXXXXXXXXXXX SRTG:[iBoot-359.3.2]
Device is now in pwned DFU Mode.
```

6. Once in pwned DFU Mode, use the -x flag to install the alloc8 exploit. This step will replace 24Kpwn exploit with alloc8.

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
If screen is not red, NOR was flashed successfully and device will reboot.
```

#### Notes:
* Installation takes about 30 seconds. Once NOR is being flashed, the screen will be green for about 10 seconds, and then your phone will reboot.

* If there are any errors before the screen turned green, it is safe to try again.

* If the screen turns red, something went wrong while your phone was being flashed. Trying again probably won't help.

* If there are no issues, the phone will reboot and automatically boot into iOS.





### 3 second delay during boot when using a phone jailbroken with alloc8

alloc8 exploit takes about 3 seconds to run.

When your phone is off, to turn it on you will need to keep holding the Power button for at least 3 seconds, or your phone will not turn on. This might be because LLB protects against accidental presses of the Power button by shutting down the phone if the power button is not being held anymore. Without an exploit it takes less than a second before this check happens, but with alloc8 exploit it will happen after about 3 seconds. It might be possible to change this behavior by patching LLB.

If your phone enters deep sleep, there will be a 3 second delay before it wakes up. This can be fixed if you disable deep sleep with a tweak from Cydia, but your phone's battery life will decrease.


### Where to download older IPSWs

Always download IPSWs directly from Apple, because IPSWs from other sites could be infected with malware.

There is a trusted site where you can find legitimate Apple download links for older IPSW files:

https://ipsw.me/


### How to create a 24Kpwn IPSW

| Version     | Tool                                                                                            | Success      |
|-------------|-------------------------------------------------------------------------------------------------|--------------|
| iOS 3.1     | [PwnageTool 3.1.3](https://github.com/axi0mX/PwnageTool-mirror/raw/master/PwnageTool_3.1.3.dmg) | Worked       |
| iOS 3.1.2/3 | [PwnageTool 3.1.5](https://github.com/axi0mX/PwnageTool-mirror/raw/master/PwnageTool_3.1.5.dmg) | Worked       |
| iOS 4.0     | [PwnageTool 4.01](https://github.com/axi0mX/PwnageTool-mirror/raw/master/PwnageTool_4.01.dmg)   | Worked       |
| iOS 4.3.3   | [redsn0w 0.9.15 beta 3](http://www.iphonehacks.com/download-redsn0w)                            | Did not work |
| iOS 5.0     | [redsn0w 0.9.15 beta 3](http://www.iphonehacks.com/download-redsn0w)                            | Worked       |
| iOS 5.0.1   | [redsn0w 0.9.15 beta 3](http://www.iphonehacks.com/download-redsn0w)                            | Worked       |
| iOS 5.1     | [redsn0w 0.9.15 beta 3](http://www.iphonehacks.com/download-redsn0w)                            | Worked       |
| iOS 5.1.1   | [redsn0w 0.9.15 beta 3](http://www.iphonehacks.com/download-redsn0w)                            | Worked       |

#### Notes on using redsn0w 0.9.15b3

```
Q: 'Will this custom IPSW be used on a newer (fixed) version of the iPhone3GS?'
A:  No [You must answer No to create a 24Kpwn IPSW using redsn0w]
```




### How to restore to a custom IPSW

 All versions of iTunes before 11.1 can be used to restore to a custom IPSW in pwned DFU Mode. You can download and install an old version of iTunes in a Windows virtual machine or use a very old Mac with an old version of iTunes. You can use any compatible tool to enter pwned DFU, but it probably won't work in a virtual machine.
 On a Mac, you can run `ipwndfu -p` in Terminal and then restore a custom IPSW in iTunes in a virtual machine.

**OR** If you are on Linux, use idevicerestore from libimobiledevice. Because of limera1n exploit issues, this might not work in a virtual machine or on a Mac.
```
idevicerestore -c -e your_custom_IPSW.ipsw
```

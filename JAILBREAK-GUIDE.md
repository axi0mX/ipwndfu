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

| iOS version | Tool                                                                                            |
|-------------|-------------------------------------------------------------------------------------------------|
| iOS 3.1     | [PwnageTool 3.1.3](https://github.com/axi0mX/PwnageTool-mirror/raw/master/PwnageTool_3.1.3.dmg) |
| iOS 3.1.2   | [PwnageTool 3.1.5](https://github.com/axi0mX/PwnageTool-mirror/raw/master/PwnageTool_3.1.5.dmg) |
| iOS 3.1.3   | [PwnageTool 3.1.5](https://github.com/axi0mX/PwnageTool-mirror/raw/master/PwnageTool_3.1.5.dmg) |
| iOS 4.0     | [PwnageTool 4.01](https://github.com/axi0mX/PwnageTool-mirror/raw/master/PwnageTool_4.01.dmg)   |
| iOS 4.3.3   | [redsn0w 0.9.15 beta 3](http://www.iphonehacks.com/download-redsn0w)                            |
| iOS 5.0     | [redsn0w 0.9.15 beta 3](http://www.iphonehacks.com/download-redsn0w)                            |
| iOS 5.0.1   | [redsn0w 0.9.15 beta 3](http://www.iphonehacks.com/download-redsn0w)                            |
| iOS 5.1     | [redsn0w 0.9.15 beta 3](http://www.iphonehacks.com/download-redsn0w)                            |
| iOS 5.1.1   | [redsn0w 0.9.15 beta 3](http://www.iphonehacks.com/download-redsn0w)                            |

#### Notes on using redsn0w 0.9.15b3

```
Q: Will this custom IPSW be used on a newer (fixed) version of the iPhone3GS?
A: No
```

You must answer No to create a 24Kpwn IPSW using redsn0w. If you did this correctly, the name of the custom IPSW from redsn0w will start with ```NO_BB_OLDROM_iPhone2,1```.


### Compatibility with older iOS versions

Newer phones might not support some older versions of iOS. You cannot brick your phone by attempting to restore an older version of iOS, so it might be worth it to try anyway. If iTunes restore fails with Error 28, the hardware of your phone is not compatible with that version of iOS.

| Manufactured | Error 28   | Success    |
|--------------|------------|------------|
| Week 38 2010 | N/A        | 3.1+       |
| Week 48 2010 | N/A        | 3.1+       |
| Week  3 2011 | 3.x        | 4.3.3+     |
| Week 14 2011 | 3.x        | 4.0+       |
| Week 23 2011 | N/A        | 3.1.2+     |
| Week 29 2011 | 3.x        | 4.0+       |
| Week 36 2011 | 3.x        | 4.0+       |
| Week 26 2012 | 3.x, 4.x   | 5.0+       |

You can find the week and year of manufacture by looking at the serial number of your phone. If your phone is from 2011 or 2012, help me expand this list and let me what versions worked or didn't work.


### Decoding iPhone 3GS serial number

```
Serial number: AABCCDDDEE
AA = Device ID
B = 2009=9, 2010=0, 2011=1, 2012=2
CC = Week of production
DDD = Unique ID
EE = Color
```


### How to restore to a custom IPSW

1. Enter DFU Mode: https://www.theiphonewiki.com/wiki/DFU_Mode

2. Run exploit to put your phone into pwned DFU Mode. You can use `./ipwndfu -p`.

3. Any version of iTunes should work. In iTunes, hold Option (or SHIFT if using Windows) and click Restore. You should be prompted to choose a file. Choose your custom IPSW.

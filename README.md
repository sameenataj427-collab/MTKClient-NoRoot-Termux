Mtkclient-NoRoot-Termux
> [!CAUTION]
> **WARNING: This tool deals with low-level device partitions. Incorrect usage can permanently HARD BRICK your device. This tool is currently in BETA TESTING. I am not responsible for any damages, data loss, or bricked phones resulting from its use. Proceed at your own risk and with extreme caution. Always backup your boot and vbmeta partitions before making changes.**
> 

# ​Key Details
​Zero Root Required: Unlike the original mtkclient, this version is designed to run in a standard Termux environment without root access.
​Optimized for Mobile: All GUI, Windows-specific, and non-essential files have been stripped to keep the script small and fast.
​Enhanced Connection: Features a custom polling loop that looks for USB devices thousands of times per second to overcome Android's single-look limitation.

​**How to use the tool**
1. ​First run the command you want.
2.​Then press Enter and wait for the text "Waiting for device connection...".
3. ​Then connect your target phone by holding its Volume Up and Volume Down buttons to the host phone via OTG.
4. ​Then quickly press OK on the Termux API popup as soon as it appears.
5. ​Then the script will handle the rest.

# Guid To Install The Tool 👇👇

First install Termux and Termux:api from Fdroid or GitHub, dont use termux from playstore, that is a outdated version and it doesn't have the nessary pakages for the tool to run

```bash
​pkg update && pkg upgrade -y
pkg install python git termux-api libusb clang binutils -y
```
```bash
python3 -m venv ~/.venv
git clone https://github.com/sameenataj427-collab/MTKClient-NoRoot-Termux
cd MTKClient-NoRoot-Termux
. ~/.venv/bin/activate
pip install -r requirements.txt
pip install .
```

​# Common Commands
​# Dump Boot and VBMeta
```bash
​python3 mtk.py r boot,vbmeta boot.img,vbmeta.img
```
# ​Unlock Bootloader
```bash
​python3 mtk.py e metadata,userdata,md_udc
```
```bash
python3 mtk.py daa
```
# ​Lock Bootloader
```bash
​python3 mtk.py oem lock
```
​# Flash Boot (for rooting)
```bash
​python3 mtk.py w boot patched_boot.img
```
# ​Read GPT Table
```
​python3 mtk.py printgpt
```
# ​Erase Userdata (Factory Reset)
```bash
​python3 mtk.py e userdata
```
# ​Flags that can be used in command and help to make work easy
​There are two types of flags that can be used; both have different formats to be used in:
​# First type:
​Format: python3 mtk.py [command] --[flag]

1. ​--force: Bypasses signature or size mismatches to force a flash.

2. ​--reset: Commands the device to reboot normally once the process is complete.

3. ​--skip [partition]: Tells the script to ignore a specific partition during a bulk read/write.

# ​Second type:
​Format: python3 mtk.py --[flag] [command]

​1. --nobatt: Used for devices that require being connected without a battery to trigger BROM.

​2. --stage2: Forces the SLA/DAA bypass payload for newer, secured MediaTek chipsets.

3. ​--debugmode: Provides a full log of the connection process to find where it is failing.

THESE ARE ONLY THE MOST USED FLAGS IN BOOTH TYPES , I CAN ADD ALL OF THEM, IF I DID THE REPOSITORY WILL BE 200 TO 300 LINS LONG AND IMPOSSIBLE TO READ

​For suggestions and bug reports contact sameenataj427@gmail.com. Thank you.

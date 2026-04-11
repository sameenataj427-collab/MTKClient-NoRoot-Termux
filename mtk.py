import os
import sys
import time
import subprocess

def sniper_loop():
    # This loop refreshes the USB device list by creating new processes
    # It bypasses the Android limitation where Termux only looks at USB once
    print("\n[#] Waiting for device connection...")
    
    count = 0
    while True:
        try:
            # Running 'termux-usb -l' as a subprocess forces a fresh scan
            # This allows the script to see the phone even if plugged in AFTER starting
            check = subprocess.check_output(["termux-usb", "-l"]).decode().strip()
            
            if "/dev/bus/usb/" in check:
                # Device detected at a specific address
                address = check.split('\n')[0]
                print(f"\n[+] Catch! Device found at: {address}")
                
                # Requesting permission and executing payload immediately
                # Single request logic prevents UI popup conflicts
                os.system(f"termux-usb -r {address}")
                print("[*] Sending payload...")
                os.system("python3 -m mtk payload")
                break
                
        except Exception:
            # Silent fail for speed to maintain the sub-1-second catch window
            pass
            
        count += 1
        # Visual heartbeat to confirm the script is actively scanning the bus
        if count % 500 == 0:
            sys.stdout.write(".")
            sys.stdout.flush()

if __name__ == "__main__":
    try:
        sniper_loop()
    except KeyboardInterrupt:
        print("\n[!] Scanner stopped by user.")
        sys.exit()

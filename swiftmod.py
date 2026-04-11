import os, sys, time, subprocess
def clear():
    os.system('clear')
def run_cmd(cmd):
    try:
        return subprocess.check_output(cmd, shell=True).decode()
    except:
        return ""
def main():
    clear()
    print("Master Station v1.1")
    print("-" * 20)
    print("1. Reboot Recovery")
    print("2. Flash Image")
    print("3. System Purge")
    print("4. Diagnostics")
    print("5. Exit")
    choice = input("\nSelect: ")
    if choice == '1':
        os.system("adb reboot recovery")
    elif choice == '3':
        os.system("rm -rf swiftmod qdl")
        print("Purge complete.")
    elif choice == '5':
        sys.exit()
if __name__ == "__main__":
    main()

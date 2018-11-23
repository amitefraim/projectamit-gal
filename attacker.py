from sys import argv
import subprocess
import time

if __name__ == '__main__':
    if len(argv) == 1:
        print("Not Enough Arguments")
        exit()

    dst = str(argv[1])
    interval = float(argv[2])
    for i in range(1,5):
        subprocess.Popen(["curl", "-d", "virus", "-X", "POST", dst, "--connect-timeout","1"], shell=False)
        time.sleep(interval)
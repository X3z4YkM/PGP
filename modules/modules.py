# clear screen
import subprocess
import os


def clear_terminal():
    # Clear the terminal screen
    subprocess.call('cls' if os.name == 'nt' else 'clear', shell=True)



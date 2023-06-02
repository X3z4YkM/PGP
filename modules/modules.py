# clear screen
import subprocess
import os
from datetime import datetime


def clear_terminal():
    # Clear the terminal screen
    subprocess.call('cls' if os.name == 'nt' else 'clear', shell=True)


PATH_PUBLIC = "public/keys"
PATH_PRIVATE = "private/keys"


def get_parameters_global(val):
    if val == "PATH_PUBLIC":
        return PATH_PUBLIC
    elif val == "PATH_PRIVATE":
        return PATH_PUBLIC


def get_current_time():
    return datetime.now()


def create_path(path):
    file_path = os.path.join(path)
    return file_path

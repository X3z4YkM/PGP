from tkinter import *

from classes.user import User
from gui.gui_main_view import gui_main_view
from globals.global_vars import global_var

root = Tk()
root.title('PGP')
root.resizable(False, False)
frame = LabelFrame(root, padx=100, pady=100)
frame.pack(padx=10, pady=10)
error_input_status = False
errorLabel = Label()
width = 400
height = 350
screenwidth = root.winfo_screenwidth()
screenheight = root.winfo_screenheight()
alignstr = '%dx%d+%d+%d' % (width, height, (screenwidth - width) / 2, (screenheight - height) / 2)
root.geometry(alignstr)
global_var['root'] = root


def login_click():
    global error_input_status
    global errorLabel
    name = nameEntry.get().split(" ")[0]
    email = emailEntry.get().split(" ")[0]
    if name == "" or email == "":
        if not error_input_status:
            error_input_status = True
            errorLabel = Label(frame, text="missing filed")
            errorLabel.pack()
    else:
        global_var['user'] = User(name, email)
        frame.destroy()
        gui_main_view(root)


nameLabel = Label(frame, text="Enter name:")
nameEntry = Entry(frame, borderwidth=2)

emailLabel = Label(frame, text="Enter email:")
emailEntry = Entry(frame, borderwidth=2)

loginbutton = Button(frame, text="logi in", command=login_click)
nameLabel.pack()
nameEntry.pack()
emailLabel.pack()
emailEntry.pack()
loginbutton.pack()

root.mainloop()

from tkinter import *

from classes.user import User
from gui.gui_main_view import gui_main_view
from globals.global_vars import global_var

root = Tk()
root.title('PGP')
root.resizable(False, False)
frame = LabelFrame(root, padx=100, pady=100)
frame.grid(row=0, column=0, padx=10, pady=10)
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
            errorLabel = Label(frame, fg='red', text="missing filed", font=("Arial", 10))
            errorLabel.grid(row=6, column=0, padx=0, pady=0)
    else:
        global_var['user'] = User(name, email)
        frame.destroy()
        gui_main_view(root)


Label_Login = Label(frame, text="========LOG IN========", font=("Arial", 10))

nameLabel = Label(frame, text="Enter name:")
nameEntry = Entry(frame, borderwidth=2)

emailLabel = Label(frame, text="Enter email:")
emailEntry = Entry(frame, borderwidth=2)

loginbutton = Button(frame, text="logi in", command=login_click)

Label_Login.grid(row=0, column=0, padx=0, pady=0)
nameLabel.grid(row=1, column=0, padx=0, pady=0)
nameEntry.grid(row=2, column=0, padx=0, pady=0)
emailLabel.grid(row=3, column=0, padx=0, pady=0)
emailEntry.grid(row=4, column=0, padx=0, pady=0)
loginbutton.grid(row=5, column=0, padx=0, pady=10)

root.mainloop()

from tkinter import *

from classes.gui_key import gui_key

root = Tk()
root.title('PGP')
root.resizable(False, False)
frame = LabelFrame(root, padx=100, pady=100)
frame.pack(padx=10, pady=10)
error_input_status = False
errorLabel = Label()


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
        frame.destroy()
        gui_key(root, frame)


nameLabel = Label(frame, text="Enter name:")
nameEntry = Entry(frame, borderwidth=2, )

emailLabel = Label(frame, text="Enter email:")
emailEntry = Entry(frame, borderwidth=2, )

loginbutton = Button(frame, text="logi in", command=login_click)
nameLabel.pack()
nameEntry.pack()
emailLabel.pack()
emailEntry.pack()
loginbutton.pack()
root.mainloop()

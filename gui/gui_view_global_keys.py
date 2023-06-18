from tkinter import *
from globals.global_vars import global_var

panel0 = None
panel1 = None
text0 = None
counter = 0
key_array = []


def prev_key():
    global counter
    if counter > 0:
        counter -= 1
        text0.delete("1.0", END)
        text0.insert(END, key_array[counter])


def next_key():
    global counter
    if counter < len(key_array) - 1:
        counter += 1
        text0.delete("1.0", END)
        text0.insert(END, key_array[counter])


def gui_view_global_keys(root):
    global panel0
    global panel1
    global text0
    global key_array

    panel0 = Frame(root, bg='lightgray', height=200)
    panel0.grid(row=0, column=0, sticky='nsew')

    panel1 = Frame(root, bg='lightgray', height=200)
    panel1.grid(row=2, column=0, sticky='nsew')

    pu_key_sc = Scrollbar(panel0, width=20)
    pu_key_sc.grid(row=0, column=1, padx=0, pady=10)

    text0 = Text(panel0, width=65, height=10)
    text0.grid(row=0, column=0, padx=10, pady=10, sticky="nsew")

    pu_key_sc.config(command=text0.yview)
    text0.config(yscrollcommand=pu_key_sc.set)

    button_next = Button(panel1, text='<<', command=prev_key)
    button_prev = Button(panel1, text='>>', command=next_key)

    button_next.grid(row=0, column=0, padx=20, pady=10)

    button_prev.grid(row=0, column=1, padx=430, pady=10)

    user = global_var.get('user')
    key_array = user.get_public_key_chain()
    if len(key_array) > 0:
        text0.delete("1.0", END)
        text0.insert(END, key_array[0])

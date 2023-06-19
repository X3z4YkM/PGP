from tkinter import *
from tkinter import simpledialog
from tkinter.ttk import Style

from globals.global_vars import global_var

panel0 = None
panel1 = None
panel2 = None
text0 = None
text1 = None
counter = 0
key_array = []


def key_array_enc_formater(key_pair):
    return f"'public_key': {key_pair.get('public_key')}\n" \
                 f"'owner_email': {key_pair.get('owner_email')}\n"\
                 f"'time_stamp': {key_pair.get('time_stamp')}\n"\
                 f"'key_id': {key_pair.get('key_id').hex()}"

def key_array_sign_formater(dec_key,key_pair):
    return f"'private_key': {dec_key}\n" \
                 f"'owner_emial': {key_pair.get('user_id')}\n" \
                 f"'time_stamp': {key_pair.get('time_stamp')}\n"\
                 f"'key_id': {key_pair.get('key_id').hex()}"

def prev_key():
    global counter
    if counter > 0:
        counter -= 1
        text0.delete("1.0", END)
        text0.insert(END, key_array_sign_formater(key_array[counter].get('key'), key_array[counter].get('pair')))

        text1.delete("1.0", END)
        text1.insert(END, key_array_enc_formater(key_array[counter].get('pair')))


def next_key():
    global counter
    if counter < len(key_array)-1:
        counter += 1
        text0.delete("1.0", END)
        text0.insert(END,  key_array_sign_formater(key_array[counter].get('key'), key_array[counter].get('pair')))

        text1.delete("1.0", END)
        text1.insert(END, key_array_enc_formater(key_array[counter].get('pair')))


def reste_view():
    global key_array
    global counter
    counter = 0
    user_input = simpledialog.askstring("Input", f"Enter password: ")
    if user_input is not None:
        user = global_var.get('user')
        key_array = user.show_key_chain(user_input)
        if len(key_array) > 0:
            text0.delete("1.0", END)
            text0.insert(END, key_array_sign_formater(key_array[0].get('key'), key_array[0].get('pair')))

            text1.delete("1.0", END)
            text1.insert(END, key_array_enc_formater(key_array[0].get('pair')))


def gui_view_keys(root):
    global panel0
    global panel1
    global panel2
    global text0
    global text1
    global key_array

    panel0 = Frame(root, bg='lightgray', height=200)
    panel0.grid(row=0, column=0, sticky='nsew')

    panel1 = Frame(root, bg='lightgray', height=200)
    panel1.grid(row=1, column=0, sticky='nsew')

    panel2 = Frame(root, bg='lightgray', height=200)
    panel2.grid(row=2, column=0, sticky='nsew')

    pr_key_sc = Scrollbar(panel1, width=20)
    pr_key_sc.grid(row=0, column=1, padx=0, pady=10)

    pu_key_sc = Scrollbar(panel0, width=20)
    pu_key_sc.grid(row=0, column=1, padx=0, pady=10)

    text0 = Text(panel0, width=65, height=10)
    text0.grid(row=0, column=0, padx=10, pady=10, sticky="nsew")

    text1 = Text(panel1, width=65, height=10)
    text1.grid(row=0, column=0, padx=10, pady=10, sticky="nsew")

    pr_key_sc.config(command=text1.yview)
    text1.config(yscrollcommand=pr_key_sc.set)

    pu_key_sc.config(command=text0.yview)
    text0.config(yscrollcommand=pu_key_sc.set)

    button_next = Button(panel2, text='<<', command=prev_key)
    button_prev = Button(panel2, text='>>', command=next_key)
    button_reset = Button(panel2, text='reset', command=reste_view)

    button_next.grid(row=0, column=0, padx=20, pady=10)
    button_reset.grid(row=0, column=1, padx=180, pady=10)
    button_prev.grid(row=0, column=2, padx=40, pady=10)

    user_input = simpledialog.askstring("Input", f"Enter password: ")
    if user_input is not None:
        user = global_var.get('user')
        key_array = user.get_private_keys(user_input)
        if len(key_array) > 0:
            text0.delete("1.0", END)
            text0.insert(END,  key_array_sign_formater(key_array[0].get('key'), key_array[0].get('pair')))

            text1.delete("1.0", END)
            text1.insert(END, key_array_enc_formater(key_array[0].get('pair')))

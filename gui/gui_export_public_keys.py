from tkinter import *
from tkinter import simpledialog, filedialog

from globals.global_vars import global_var

panel0 = None
panel1 = None
panel2 = None
key_id_arr = None
list_ids = None
user_input = None

def format_key(pair):
    return f"{pair.get('owner_email')}_{pair.get('key_id').hex()}_{pair.get('public_key')[0:100]}"


def search_for_id(value):
    for elem in key_id_arr:
        if elem.get('pair').get('key_id').hex() == value:
            return elem.get('key_id')


def export():
    selected_indices = list_ids.curselection()
    user = global_var.get('user')

    index_to_delete = []

    for index in reversed(selected_indices):
        try:
            file_path = filedialog.asksaveasfilename(defaultextension=".pem")
            if file_path:
                item = list_ids.get(index)
                key_id = search_for_id(item)
                user.export_public_key(file_path, key_id)
                index_to_delete.append(index)
        except ValueError:
            pass
    for index in index_to_delete:
        list_ids.delete(index)


def reset():
    global user_input
    global key_id_arr

    user = global_var.get('user')
    key_id_arr = user.get_public_key_chain()
    for elem in key_id_arr:
        list_ids.insert(END, format_key(elem))


def gui_export_public_keys(root):
    global panel0
    global panel1
    global panel2
    global key_id_arr
    global list_ids
    global user_input

    panel0 = Frame(root, bg='lightgray', height=100)
    panel0.grid(row=0, column=0, sticky='nsew')

    panel1 = Frame(root, bg='lightgray', height=100)
    panel1.grid(row=1, column=0, sticky='nsew')

    panel2 = Frame(root, bg='lightgray', height=100)
    panel2.grid(row=2, column=0, sticky='nsew')

    list_ids = Listbox(panel1, selectmode=EXTENDED, width=80, height=22)
    list_ids.grid(row=0, column=0, padx=55, pady=10)

    button_export = Button(panel2, text="export", command=export)
    button_export.grid(row=0, column=0, padx=100, pady=10)

    button_reset = Button(panel2, text="reset", command=reset)
    button_reset.grid(row=0, column=1, padx=200, pady=10)

    title_label = Label(panel0, bg='lightgray', text="==============================\n|   " +
                                                     " EXPORT PUBLIC KEYS    |\n==============================")
    title_label.grid(row=0, column=0, padx=160, pady=0)

    user = global_var.get('user')
    key_id_arr = user.get_public_key_chain()
    for elem in key_id_arr:
        list_ids.insert(END, format_key(elem))

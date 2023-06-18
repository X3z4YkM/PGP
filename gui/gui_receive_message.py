import tkinter
from tkinter import *
from tkinter import filedialog as fd, simpledialog, filedialog
import classes.pgp as pgp
from globals.global_vars import global_var

canvas = None
import json

receive_button = None

files = []
list_files = None
error_label = None
Text_recodr = None


def select_file():
    filetypes = (
        ('msg files', '*.txt *.msg *.bin'),
    )
    filename = fd.askopenfilename(
        title='Open a file',
        initialdir='/',
        filetypes=filetypes
    )
    files.append(filename)
    list_files.insert(tkinter.END, filename)


def remove_file():
    selected_indices = list_files.curselection()
    for index in reversed(selected_indices):
        item = list_files.get(index)
        files.remove(item)
        list_files.delete(index)


def configure_scroll_region(event):
    canvas.configure(scrollregion=canvas.bbox("all"))


def scroll_canvas(*args):
    canvas.yview(*args)


my_received = None


def decode_message():
    byte_stream = 123
    with open(files[0], 'rb') as file:
        byte_stream = file.read()
    try:
        data, key_id = pgp.extract_and_validate_message_1(byte_stream)
        private_key = None
        user_input = None
        global my_received
        global panle_error
        global panel_success

        if key_id:
            private_key = global_var.get('user').search_private_key(key_id)
            user_input = simpledialog.askstring(f"Input for key_id : {hex(key_id)}", f"Enter password: ")
        my_received = pgp.extract_and_validate_message_2(data, global_var.get('user'), user_input)
        global Text_recodr
        panle_error.grid_remove()
        Text_recodr.insert(END, json.dumps(my_received, indent=4))
        panel_success.grid(row=5, column=0, sticky='nsew')
        message_success = Label(panel_success, bg='lightgray', fg='green', text='SUCCESS')
    except ValueError as error:
        panel_success.grid_remove()
        panle_error.grid(row=4, column=0, sticky='nsew')
        message_error = Label(panle_error, bg='lightgray', fg='red', text=error)


frame = None
panle_error = None
panel_success = None


def export():
    global my_received
    file_path = filedialog.asksaveasfilename(defaultextension=".txt")
    if file_path:
        with open(file_path, 'w') as file:
            file.write(json.dumps(my_received, indent=4))



def configure_scroll_region(event):
    canvas.configure(scrollregion=canvas.bbox("all"))


def scroll_canvas(*args):
    canvas.yview(*args)


def gui_receive_mess(root):
    global canvas
    global frame
    canvas = Canvas(root, bg='lightgray', width=560, height=510)
    canvas.grid(row=0, column=0, padx=0, pady=0)
    scrollbar = Scrollbar(root, orient=VERTICAL, command=canvas.yview)
    scrollbar.grid(row=0, column=1, sticky="ns")
    canvas.configure(yscrollcommand=scrollbar.set)
    frame = Frame(canvas)
    canvas.create_window((0, 0), window=frame, anchor="nw")

    panel0 = Frame(frame, bg='lightgray', height=100)
    panel0.grid(row=0, column=0, sticky='nsew')
    panel1 = Frame(frame, bg='lightgray', height=100)
    panel1.grid(row=1, column=0, sticky='nsew')
    panel2 = Frame(frame, bg='lightgray', height=100)
    panel2.grid(row=2, column=0, sticky='nsew')
    global list_files
    list_files = Listbox(panel0, selectmode=EXTENDED, width=80, height=8)
    list_files.grid(row=0, column=0, padx=40, pady=10)

    open_button = Button(
        panel1,
        text='Open a File',
        command=select_file
    )

    open_button.grid(row=1, column=0, padx=50, pady=10)
    remove_button = Button(
        panel1,
        text='Remove file',
        command=lambda: remove_file()
    )
    remove_button.grid(row=1, column=2, padx=50, pady=0)
    frame.bind("<Configure>", configure_scroll_region)
    scrollbar.config(command=scroll_canvas)

    global receive_button
    receive_button = Button(
        panel1,
        text='Decode message',
        command=lambda: decode_message()
    )
    receive_button.grid(row=1, column=1, padx=50, pady=10)

    button_export = Button(panel2, text="export", command=export)
    button_export.grid(row=3, column=0, padx=100, pady=10)

    global Text_recodr

    Text_recodr = Text(panel2, width=50, height=15)
    Text_recodr.grid(row=2, column=0, padx=60, pady=10)
    scrollbar = Scrollbar(panel2, command=Text_recodr.yview)
    scrollbar.grid(row=2, column=1, sticky='ns')
    Text_recodr.config(yscrollcommand=scrollbar.set)
    frame.bind("<Configure>", configure_scroll_region)
    scrollbar.config(command=scroll_canvas)
    global panle_error
    global panel_success
    panle_error = Frame(frame, bg='lightgray', height=100)
    panle_error.grid_remove()
    panel_success = Frame(frame, bg='lightgray', height=100)
    panel_success.grid_remove()

import tkinter
from tkinter import *
from tkinter import filedialog as fd, font, simpledialog
from globals.global_vars import global_var

files = []
list_files = None

error_label = None
panel0 = None
panel1 = None
panel2 = None
panel3 = None


def error_handler(error):
    global panel3
    global error_label
    if error_label is not None:
        error_label.destroy()
    custom_font = font.Font(size=10)
    error_label = Label(panel3, bg='lightgray', text=error, foreground='red', font=custom_font).grid(row=2, column=0,
                                                                                                     padx=10, pady=20)


def import_files():
    global files
    if files:
        user = global_var.get('user')
        for index, path in enumerate(files):
            try:
                user.import_public_key(path)
                files.remove(path)
                list_files.delete(index)
            except ValueError as error:
                error_string = str(error)
                error_handler(error_string[:30])
            except OSError as error:
                error_string = str(error)
                error_handler(error_string[:10])


def select_file():
    filetypes = (
        ('pem files', '*.pem'),
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


def gui_import_public_key(root):
    global panel1
    global panel2
    global panel3
    global panel0

    panel0 = Frame(root, bg='lightgray', height=100)
    panel0.grid(row=0, column=0, sticky='nsew')

    panel1 = Frame(root, bg='lightgray', height=100)
    panel1.grid(row=1, column=0, sticky='nsew')

    panel2 = Frame(root, bg='lightgray', height=100)
    panel2.grid(row=2, column=0, sticky='nsew')

    panel3 = Frame(root, bg='lightgray', height=100)
    panel3.grid(row=3, column=0, sticky='nsew')

    global list_files
    list_files = Listbox(panel1, selectmode=EXTENDED, width=80, height=12)
    list_files.grid(row=0, column=0, padx=55, pady=20)

    import_button = Button(
        panel2,
        text='Import files',
        command=lambda: import_files()
    )
    import_button.grid(row=1, column=0, padx=62, pady=0)

    open_button = Button(
        panel2,
        text='Open a File',
        command=select_file
    )
    open_button.grid(row=1, column=1, padx=70, pady=10)
    remove_button = Button(
        panel2,
        text='Remove file',
        command=lambda: remove_file()
    )
    remove_button.grid(row=1, column=2, padx=50, pady=0)
    title_label = Label(panel0, bg='lightgray', text="==============================\n|    " +
                                                     " IMPORT PUBLIC KEYS    |\n==============================")
    title_label.grid(row=0, column=0, padx=160, pady=0)

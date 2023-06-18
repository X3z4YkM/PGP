import tkinter
from tkinter import *
from tkinter import filedialog as fd

canvas = None

files = []
list_files = None
error_label = None

def select_file():
    filetypes = (
        ('msg files', '*.msg'),
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


def gui_recive_mess(root):
    global canvas
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

    global list_files
    list_files = Listbox(panel0, selectmode=EXTENDED, width=80, height=8)
    list_files.grid(row=0, column=0, padx=40, pady=10)

    open_button = Button(
        panel1,
        text='Open a File',
        command=select_file
    )

    open_button.grid(row=1, column=0, padx=70, pady=10)
    remove_button = Button(
        panel1,
        text='Remove file',
        command=lambda: remove_file()
    )
    remove_button.grid(row=1, column=1, padx=200, pady=0)
    frame.bind("<Configure>", configure_scroll_region)
    scrollbar.config(command=scroll_canvas)

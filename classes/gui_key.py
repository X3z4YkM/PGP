from tkinter import *
from tkinter import filedialog as fd

files = ()


def import_files(files=None):
    print(files)


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





def gui_key(root, frame):
    frame = LabelFrame(root, padx=100, pady=100)
    frame.pack(padx=10, pady=10)
    list_files = Listbox(frame, height=20, width=100, selectmode=EXTENDED)
    list_files.pack()
    open_button = Button(
        frame,
        text='Open a File',
        command=select_file
    )
    open_button.pack()
    open_button.pack(expand=True)
    import_button = Button(
        frame,
        text='Import files',
        command=lambda: import_files()
    )
    import_button.pack()
    import_button.pack(expand=True)

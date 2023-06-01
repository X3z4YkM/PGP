from tkinter import *
from tkinter import font
from tkinter.ttk import Combobox

from globals.global_vars import global_var
from gui.gui_export_pr_keys import gui_export_private_keys
from gui.gui_export_public_keys import gui_export_public_keys
from gui.gui_import_pr_keys import gui_import_private_key
from gui.gui_import_pu_keys import gui_import_public_key
from gui.gui_key_generator import gui_key_generator
from gui.gui_message_send import gui_mess_send
from gui.gui_view_global_keys import gui_view_global_keys
from gui.gui_view_private_keys import gui_view_keys

panel = None


def create_main_panel():
    global panel
    if panel is not None:
        panel.destroy()
    panel = Frame(global_var.get('root'), bg='lightgray', highlightbackground="black", highlightthickness=1, height=100)
    panel.grid(row=1, column=0, sticky='nsew', padx=10, pady=10)


def info_info_user():
    if global_var.get('LAST_SELECTED_MENU_ITEM') != 'user info':
        create_main_panel()
        panel['padx'] = 150
        user = global_var.get('user')
        info = Label(panel,
                     bg='lightgray',
                     font=('Arial', 12),
                     text='=========[USER INFO]=========\n\n' + user.get_info() + '\n=========================')
        info.grid(row=0, column=0, padx=0, pady=0)
        global_var['LAST_SELECTED_MENU_ITEM'] = 'user info'


def key_gen_key():
    if global_var.get('LAST_SELECTED_MENU_ITEM') != 'generate keys':
        create_main_panel()
        gui_key_generator(panel)


def file_imp_pr_key():
    if global_var.get('LAST_SELECTED_MENU_ITEM') != 'import pr key':
        create_main_panel()
        global panel
        gui_import_private_key(panel)
        global_var['LAST_SELECTED_MENU_ITEM'] = 'import pr key'


def file_imp_pu_key():
    if global_var.get('LAST_SELECTED_MENU_ITEM') != 'import pu key':
        create_main_panel()
        global panel
        gui_import_public_key(panel)
        global_var['LAST_SELECTED_MENU_ITEM'] = 'import pu key'


def view_view_pr_keys():
    if global_var.get('LAST_SELECTED_MENU_ITEM') != 'view private keys':
        create_main_panel()
        global panel
        gui_view_keys(panel)
        global_var['LAST_SELECTED_MENU_ITEM'] = 'view private keys'


def file_export_pr_keys():
    if global_var.get('LAST_SELECTED_MENU_ITEM') != 'export pr keys':
        create_main_panel()
        global panel
        gui_export_private_keys(panel)
        global_var['LAST_SELECTED_MENU_ITEM'] = 'export pr keys'


def file_export_pu_keys():
    if global_var.get('LAST_SELECTED_MENU_ITEM') != 'export pu keys':
        create_main_panel()
        global panel
        gui_export_public_keys(panel)
        global_var['LAST_SELECTED_MENU_ITEM'] = 'export pu keys'


def view_view_global_pu_keys():
    if global_var.get('LAST_SELECTED_MENU_ITEM') != 'view global keys':
        create_main_panel()
        global panel
        gui_view_global_keys(panel)
        global_var['LAST_SELECTED_MENU_ITEM'] = 'view global keys'


def mess_send_message():
    if global_var.get('LAST_SELECTED_MENU_ITEM') != 'view global keys':
        create_main_panel()
        global panel
        gui_mess_send(panel)
        global_var['LAST_SELECTED_MENU_ITEM'] = 'view global keys'
    pass


def mess_recive_message():
    pass


def gui_main_view(root):
    root.resizable(width=False, height=True)
    width = 600
    height = 550
    root.minsize(width=width, height=height)
    screenwidth = root.winfo_screenwidth()
    screenheight = root.winfo_screenheight()
    alignstr = '%dx%d+%d+%d' % (width, height, (screenwidth - width) / 2, (screenheight - height) / 2)
    root.geometry(alignstr)

    menu_bar = Menu(root)
    root.config(menu=menu_bar)

    file_menu = Menu(menu_bar, tearoff=0)
    file_menu.add_command(label='import private keys', command=file_imp_pr_key)
    file_menu.add_command(label='export private keys', command=file_export_pr_keys)
    file_menu.add_command(label='import public keys', command=file_imp_pu_key)
    file_menu.add_command(label='export public keys', command=file_export_pu_keys)
    menu_bar.add_cascade(label='File', menu=file_menu)

    key_menu = Menu(menu_bar, tearoff=0)
    key_menu.add_command(label='generate keys', command=key_gen_key)
    menu_bar.add_cascade(label='Keys', menu=key_menu)

    view_menu = Menu(menu_bar, tearoff=0)
    view_menu.add_command(label='view private keys', command=view_view_pr_keys)
    view_menu.add_command(label='view global public keys', command=view_view_global_pu_keys)
    menu_bar.add_cascade(label='View', menu=view_menu)

    mess_menu = Menu(menu_bar, tearoff=0)
    mess_menu.add_command(label='send message', command=mess_send_message)
    mess_menu.add_command(label='receive message', command=mess_recive_message)
    menu_bar.add_cascade(label='Message', menu=mess_menu)

    info_menu = Menu(menu_bar, tearoff=0)
    info_menu.add_command(label='user info', command=info_info_user)
    menu_bar.add_cascade(label='Info', menu=info_menu)

    global panel
    panel = Frame(root, bg='lightgray', highlightbackground="black", highlightthickness=1, height=100)
    panel.grid(row=1, column=0, sticky='nsew')
    root.grid_rowconfigure(1, weight=1)
    root.grid_columnconfigure(0, weight=1)
    info_info_user()

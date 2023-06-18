from globals.global_vars import global_var
from tkinter import *
from tkinter import font
from tkinter.ttk import Combobox

error_label = None

panel = None


def error_handler(error, row):
    global panel
    global error_label
    if error_label is not None:
        error_label.destroy()
    custom_font = font.Font(size=10)
    error_label = Label(panel, bg='lightgray', text=error, foreground='red', font=custom_font).grid(row=row, column=0,
                                                                                                    padx=10, pady=20)


def success_handler():
    global panel
    global error_label
    if error_label is not None:
        error_label.destroy()
    custom_font = font.Font(size=10)
    error_label = Label(panel, bg='lightgray', text='[SUCCESS]: KEYS CREATED', foreground='green',
                        font=custom_font).grid(row=5, column=0,
                                               padx=10, pady=20)


def generate_keys(*argz):
    selected_alg = argz[0].get()
    selected_size = argz[1].get()
    password = argz[2].get()
    password_confirm = argz[3].get()
    if selected_alg == '':
        error_handler('[ERROR]: MISSING ALGORITHM!!', 5)
    elif selected_size == '':
        error_handler('[ERROR]: MISSING LENGTH!!', 5)
    elif len(password) < 5:
        error_handler('[ERROR]: PASSWORD TO SHORT!!', 5)
    elif password != password_confirm:
        error_handler('[ERROR]: PASSWORDS DO NOT MATCH!!', 5)
    else:
        selected_size = int(selected_size)
        try:
            global_var.get('user').generate_key_pair(selected_alg, selected_size, password)
            success_handler()
            argz[2].delete(0, END)
            argz[3].delete(0, END)
        except ValueError as error:
            error_label('[ERROR WHEN CREATING KEYS]', 5)
            print(str(error))


def gui_key_generator(panelin):
    global panel
    panel = panelin
    panel['padx'] = 10
    panel['pady'] = 10
    drop_down_list = Combobox(panel, values=['RSA', 'DSA/Elgamal'])
    drop_down_list.grid(row=0, column=1, padx=0, pady=0)

    drop_down_label = Label(panel, bg='lightgray', text='[SELECT ASYMMETRIC ALGORITHM ]: ')
    drop_down_label.grid(row=0, column=0, padx=10, pady=10)

    global_var['LAST_SELECTED_MENU_ITEM'] = 'generate keys'

    len_input_label = Label(panel, bg='lightgray', text='[INPUT KEY LENGTH] (1024 or 2048): ')
    len_input_label.grid(row=1, column=0, padx=10, pady=10)
    len_input = Combobox(panel, values=['1024', '2048'])
    len_input.grid(row=1, column=1, padx=0, pady=0)

    pass_input_label = Label(panel, bg='lightgray', text='[INPUT PASSWORD]: ')
    pass_input_label.grid(row=2, column=0, padx=10, pady=10)
    pass_input = Entry(panel, borderwidth=2, show="*")
    pass_input.grid(row=2, column=1, padx=0, pady=0)

    pass_con_input_label = Label(panel, bg='lightgray', text='[CONFIRM PASSWORD]: ')
    pass_con_input_label.grid(row=3, column=0, padx=10, pady=10)
    pass_con_input = Entry(panel, borderwidth=2, show="*")
    pass_con_input.grid(row=3, column=1, padx=0, pady=0)

    gen_button = Button(panel, text='generate',
                        command=lambda: generate_keys(drop_down_list, len_input, pass_input, pass_con_input))
    gen_button.grid(row=4, column=1, padx=0, pady=20)

import time
from tkinter import *
from tkinter import filedialog as fd, simpledialog
from globals.global_vars import global_var
from classes.pgp import construct_message
from modules import constants

panel0 = None
panel1 = None
panel2 = None
panel3 = None
panel4 = None
panel5 = None
panel6 = None
panel7 = None
panel8 = None
panel9 = None
panel10 = None
file_path = None
file_name = None
info = {}
rsa_cb = None
dsa_elg_cb = None
signature_ckbox = None
sign_var = None
rsa_var = None
dsa_var = None
root_global = None
text1 = None
user_input = None
key_array_sign = []
key_array_enc = []
en_var = None
aes_var = None
des3_var = None
encrypt_xbox = None
aes_cb = None
des3_cb = None
text1_en = None
zip_env = None
radix64_ven = None
text_input_text = None
panelErrorPanel = None
labelErrormMessage = None




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

def select_directory():
    global file_path
    directory = fd.askdirectory()
    if directory:
        file_path.configure(state=NORMAL)
        file_path.delete(0, END)
        file_path.insert(0, directory)
        file_path.configure(state=DISABLED)


selected = 0
counter_sign = 0




def prev_key():
    global counter_sign
    global text1
    global key_array_sign
    key_array_sign
    if counter_sign > 0:
        counter_sign -= 1
        text1.delete("1.0", END)
        text1.insert(END, key_array_sign_formater(key_array_sign[counter_sign].get('key'),key_array_sign[counter_sign].get('pair')))


def next_key():
    global counter_sign
    global text1
    global key_array_sign
    if counter_sign < len(key_array_sign) - 1:
        counter_sign += 1
        text1.delete("1.0", END)
        text1.insert(END, key_array_sign_formater(key_array_sign[counter_sign].get('key'),key_array_sign[counter_sign].get('pair')))


def reste_view():
    global counter_sign
    global text1
    global key_array_sign

    counter_sign = 0

    user_input = simpledialog.askstring("Input", f"Enter password: ")
    if user_input is not None:
        user = global_var.get('user')
        if selected == 1:
            counter_sign = 0
            key_array_sign = user.get_by_header('RSA', user_input)
            text1.delete("1.0", END)
            text1.insert(END, key_array_sign_formater(key_array_sign[0].get('key'), key_array_sign[0].get('pair')))
        elif selected == 2:
            counter_sign = 0
            key_array_sign = user.get_by_header('DSA', user_input)
            text1.delete("1.0", END)
            text1.insert(END, key_array_sign_formater(key_array_sign[0].get('key'),key_array_sign[0].get('pair')))


was_selected = 0


def toggle_options_sig():
    global panel2
    global selected
    global panel3
    global key_array_sign
    global counter_sign
    global was_selected
    global selected
    global rsa_var
    global dsa_var
    global panel3
    global panel4
    global key_array_sign
    global counter_sign
    global text1
    global user_input
    global sign_var

    if sign_var.get():
        if panel3:
            panel3.destroy()
            panel4.destroy()
        panel3 = Frame(root_global, bg='lightgray', height=100)
        panel3.grid(row=4, column=0, sticky='nsew')

        if selected != 0:
            user_input = simpledialog.askstring("Input", f"Enter password: ")

        pr_key_sc = Scrollbar(panel3, width=20)
        pr_key_sc.grid(row=0, column=1, padx=0, pady=10)
        text1 = Text(panel3, width=65, height=10)
        text1.grid(row=0, column=0, padx=10, pady=10, sticky="nsew")
        pr_key_sc.config(command=text1.yview)
        text1.config(yscrollcommand=pr_key_sc.set)
        panel4 = Frame(root_global, bg='lightgray', height=100)
        panel4.grid(row=5, column=0, sticky='nsew')
        button_next = Button(panel4, text=">>", command=next_key)
        button_prev = Button(panel4, text="<<", command=prev_key)
        button_reset = Button(panel4, text="reset", command=reste_view)
        button_next.grid(row=1, column=2, padx=30, pady=10)
        button_reset.grid(row=1, column=1, padx=20, pady=10)
        button_prev.grid(row=1, column=0, padx=10, pady=10)

        user = global_var.get('user')

        if selected == 1:
            counter_sign = 0
            key_array_sign = user.get_by_header('RSA', user_input)
            text1.delete("1.0", END)
            if len(key_array_sign) > 0:
                text1.insert(END, key_array_sign_formater(key_array_sign[0].get('key'),key_array_sign[0].get('pair')))
        elif selected == 2:
            counter_sign = 0
            key_array_sign = user.get_by_header('DSA', user_input)
            text1.delete("1.0", END)
            if len(key_array_sign) > 0:
                text1.insert(END, key_array_sign_formater(key_array_sign[0].get('key'), key_array_sign[0].get('pair')))
    else:
        panel3.destroy()
        panel4.destroy()


def show_key_sig(num):
    global selected
    global rsa_var
    global dsa_var
    global panel3
    global panel4
    global key_array_sign
    global counter_sign
    global text1
    global user_input
    global sign_var
    global panel2
    global panel5
    global panel6
    global panel7
    global panel8
    global aes_var
    global des3_var

    if not rsa_var.get() and not dsa_var.get():
        if panel2:
            panel2.grid_remove()
        if panel5:
            panel5.grid_remove()
        if panel6:
            panel6.grid_remove()
        if panel7:
            panel7.grid_remove()
            panel8.grid_remove()
        if panel3:
            panel3.destroy()
            panel4.destroy()
        sign_var.set(False)
        en_var.set(False)
        aes_var.set(False)
        des3_var.set(False)
        selected = 0
    else:
        if selected == 1 and dsa_var.get():
            rsa_var.set(False)
        elif selected == 2 and rsa_var.get():
            dsa_var.set(False)
        panel2.grid(row=2, column=0, sticky='nsew')
        panel5.grid(row=6, column=0, sticky='nsew')

    selected = num
    if sign_var.get():
        user = global_var.get('user')
        if selected == 1:
            counter_sign = 0
            key_array_sign = user.get_by_header('RSA', user_input)
            text1.delete("1.0", END)
            if len(key_array_sign) > 0:
                text1.insert(END, key_array_sign_formater(key_array_sign[0].get('key'),key_array_sign[0].get('pair')))
        elif selected == 2:
            counter_sign = 0
            key_array_sign = user.get_by_header('DSA', user_input)
            text1.delete("1.0", END)
            if len(key_array_sign) > 0:
                text1.insert(END, key_array_sign_formater(key_array_sign[0].get('key'),key_array_sign[0].get('pair')))


selected_enc = 0
counter_enc = 0


def prev_key_en():
    global counter_enc
    global text1_en
    global key_array_enc
    key_array_enc
    if counter_enc > 0:
        counter_enc -= 1
        text1_en.delete("1.0", END)
        text1_en.insert(END, key_array_enc_formater(key_array_enc[counter_enc].get('pair')))


def next_key_en():
    global counter_enc
    global text1_en
    global key_array_enc

    if counter_enc < len(key_array_enc) - 1:
        counter_enc += 1
        text1_en.delete("1.0", END)
        text1_en.insert(END, key_array_enc_formater(key_array_enc[counter_enc].get('pair')))

def resetPanles():
    global panel2
    global panel3
    global panel4
    global panel5
    global panel6
    global panel7
    global panel8
    global selected_enc
    global selected
    global key_array_enc
    global key_array_sign
    global zip_env
    global radix64_ven
    global file_name
    global sign_var
    global rsa_var
    global dsa_var

    if panel3:
        panel3.destroy()
        panel4.destroy()

    if panel2:
        panel2.grid_remove()
    if panel5:
        panel5.grid_remove()
    if panel6:
        panel6.grid_remove()
    if panel7:
        panel7.grid_remove()
        panel8.grid_remove()
    if panel3:
        panel3.destroy()
        panel4.destroy()

    file_name.delete(0, END)
    sign_var.set(False)
    en_var.set(False)
    aes_var.set(False)
    des3_var.set(False)
    zip_env.set(False)
    radix64_ven.set(False)
    sign_var.set(False)
    rsa_var.set(False)
    dsa_var.set(False)
    selected = 0
    selected_enc = 0
    key_array_enc = []
    key_array_sign = []

def key_show_enc(num):
    global selected_enc
    global aes_var
    global des3_var
    global panel7
    global panel8
    global text1_en
    global counter_enc
    global key_array_enc
    global en_var

    if panel7:
        panel7.destroy()
        panel8.destroy()
    panel7 = Frame(root_global, bg='lightgray', height=100)
    panel7.grid(row=8, column=0, sticky='nsew')

    selected_enc = num

    if selected_enc == 1:
        aes_var.set(True)
        des3_var.set(False)
    elif selected_enc == 2:
        des3_var.set(True)
        aes_var.set(False)

    pu_key_sc = Scrollbar(panel7, width=20)
    pu_key_sc.grid(row=0, column=1, padx=0, pady=10)
    text1_en = Text(panel7, width=65, height=10)
    text1_en.grid(row=0, column=0, padx=10, pady=10, sticky="nsew")
    pu_key_sc.config(command=text1_en.yview)
    text1_en.config(yscrollcommand=pu_key_sc.set)
    panel8 = Frame(root_global, bg='lightgray', height=100)
    panel8.grid(row=9, column=0, sticky='nsew')
    button_next = Button(panel8, text=">>", command=next_key_en)
    button_prev = Button(panel8, text="<<", command=prev_key_en)
    button_next.grid(row=1, column=2, padx=30, pady=10)
    button_prev.grid(row=1, column=0, padx=10, pady=10)
    global_var.get('root').configure(height=800)

    if en_var.get():
        user = global_var.get('user')
        counter_enc = 0
        key_array_enc = user.get_public_key_chain_alt()
        text1_en.delete("1.0", END)
        if len(key_array_enc) > 0:
            text1_en.insert(END, key_array_enc_formater(key_array_enc[0].get('pair')))


def to_en_op():
    global panel5
    global selected_enc
    global panel6
    global panel7
    global panel8
    global counter_enc

    if panel6.winfo_viewable():
        aes_var.set(False)
        des3_var.set(False)
        panel6.grid_remove()
        counter_enc = 0
        selected_enc = 0
        if panel7:
            panel7.grid_remove()
            panel8.grid_remove()
    else:
        panel6.grid(row=7, column=0, sticky='nsew')
        if panel7:
            panel7.grid_remove()
            panel8.grid_remove()


def send_message():
    global zip_env
    global radix64_ven
    global sign_var
    global rsa_var
    global dsa_var
    global aes_var
    global des3_var
    global en_var
    global text_input_text
    global user_input
    global file_name

    message_path_full = file_path.get() + '/' + file_name.get()

    message = None
    if text_input_text.get("1.0", END).strip():
        message = text_input_text.get("1.0", END)

    Sing_message_selected = False

    Sign_method = constants.SIGN_ENC_NONE
    if sign_var.get():
        Sing_message_selected = True
        if rsa_var.get():
            Sign_method = constants.SIGN_ENC_RSA
        elif dsa_var.get():
            Sign_method = constants.SIGN_ENC_DSA_ELGAMAL

    private_sing_key_selected = None
    global counter_sign
    if sign_var.get() and (rsa_var.get() or dsa_var.get()):
        if len(key_array_sign) > 0:
            private_sing_key_selected = key_array_sign[counter_sign].get('pair')

    Encrypt_message_selected = False

    Encrypt_method = constants.ALGORITHM_NONE
    if en_var.get():
        Encrypt_message_selected = True
        if aes_var.get():
            Encrypt_method = constants.ALGORITHM_AES
        elif des3_var.get():
            Encrypt_method = constants.ALGORITHM_DES3

    public_encrypt_key_selected = None
    global counter_enc
    if en_var.get() and (aes_var.get() or des3_var.get()):
        if len(key_array_enc) > 0:
            public_encrypt_key_selected = key_array_enc[counter_enc].get('pair')

    Zip_Selected = False

    if zip_env.get():
        Zip_Selected = True

    Radix64_Selected = False

    if radix64_ven.get():
        Radix64_Selected = True

    Error_Status = None
    Error_Message = ""
    # error check
    if len(file_path.get()) == 0:
        Error_Status = True
        Error_Message += "Path not selected\n"
    if len(file_name.get()) == 0:
        Error_Status = True
        Error_Message += "File name not input\n"
    if public_encrypt_key_selected is None and Encrypt_message_selected:
        Error_Status = True
        Error_Message += "No Public keys found\n"
    if private_sing_key_selected is None and Sing_message_selected:
        Error_Status = True
        Error_Message += "No Private keys found\n"

    global root_global
    global labelErrormMessage
    global panelErrorPanel
    print(user_input)
    if not Error_Status:
        try:
            encrypted_message = construct_message(file_name.get(), message, time.time(), user_input,
                            private_sing_key_selected, public_encrypt_key_selected,
                            Sign_method, Encrypt_method, Sing_message_selected, Zip_Selected, Radix64_Selected)
            with open(message_path_full, 'wb') as file:
                file.write(encrypted_message)

            panelErrorPanel = Frame(root_global, bg='lightgray', height=100)
            panelErrorPanel.grid(row=20, column=0, sticky='nsew')
            labelErrormMessage = Label(panelErrorPanel, bg='lightgray', fg='green', text="Message Send ")
            labelErrormMessage.grid(row=0, column=0, padx=0, pady=2)
            text_input_text.delete('1.0', END)
            file_name.config(text="")
            file_path.configure(state=NORMAL)
            file_path.delete(0, END)
            file_path.insert(0, "")
            file_path.configure(state=DISABLED)
            resetPanles()

        except ValueError as error:
            print(str(error))
            panelErrorPanel = Frame(root_global, bg='lightgray', height=100)
            panelErrorPanel.grid(row=20, column=0, sticky='nsew')
            labelErrormMessage = Label(panelErrorPanel, bg='lightgray', fg='red', text=str(error))
            labelErrormMessage.grid(row=0, column=0, padx=0, pady=2)

    else:
        panelErrorPanel = Frame(root_global, bg='lightgray', height=100)
        panelErrorPanel.grid(row=20, column=0, sticky='nsew')
        labelErrormMessage = Label(panelErrorPanel, bg='lightgray', fg='red', text=Error_Message)
        labelErrormMessage.grid(row=0, column=0, padx=0, pady=2)


canvas = None


def configure_scroll_region(event):
    canvas.configure(scrollregion=canvas.bbox("all"))


def scroll_canvas(*args):
    canvas.yview(*args)


def gui_mess_send(rootin):
    global canvas
    canvas = Canvas(rootin, bg='lightgray', width=560, height=510)
    canvas.grid(row=0, column=0, padx=0, pady=0)
    scrollbar = Scrollbar(rootin, orient=VERTICAL, command=canvas.yview)
    scrollbar.grid(row=0, column=1, sticky="ns")
    canvas.configure(yscrollcommand=scrollbar.set)
    frame = Frame(canvas)
    canvas.create_window((0, 0), window=frame, anchor="nw")

    global panel0
    global file_path
    global file_name
    global panel1
    global panel2
    global rsa_cb
    global dsa_elg_cb
    global signature_ckbox
    global sign_var
    global rsa_var
    global dsa_var
    global root_global
    global panel5
    global panel6
    global encrypt_xbox
    global en_var
    global aes_var
    global des3_var
    global aes_cb
    global des3_cb
    global labelErrormMessage



    root_global = frame
    panel0 = Frame(frame, bg='lightgray', height=100)
    panel0.grid(row=0, column=0, sticky='nsew')

    panel1 = Frame(frame, bg='lightgray', height=100)
    panel1.grid(row=1, column=0, sticky='nsew')

    panel2 = Frame(frame, bg='lightgray', height=100)
    panel2.grid(row=2, column=0, sticky='nsew')

    # ----------------FILE-------------
    file_path_label = Label(panel0, bg='lightgray', text="[SELECET PPATH]")
    file_path_label.grid(row=0, column=0, padx=10, pady=1)
    file_path = Entry(panel0, width=50)
    file_path.grid(row=1, column=0, padx=10, pady=10)
    file_path.configure(state=DISABLED)

    file_path_button = Button(panel0, text='path', width=10, command=select_directory)
    file_path_button.grid(row=1, column=1, padx=10, pady=10)

    file_name_label = Label(panel0, bg='lightgray', text="[INPUT FILE NAME] ")
    file_name_label.grid(row=2, column=0, padx=0, pady=2)
    file_name = Entry(panel0, width=20)
    file_name.grid(row=3, column=0, padx=0, pady=2)

    # --------------AUTENTICNOST-------------
    sign_lib = Label(panel2, bg='lightgray', text="Signe the message:")
    sign_lib.grid(row=2, column=0, padx=0, pady=2)

    sign_var = BooleanVar()
    rsa_var = BooleanVar()
    dsa_var = BooleanVar()

    signature_ckbox = Checkbutton(panel2, bg='lightgray', text="", command=toggle_options_sig, variable=sign_var)
    signature_ckbox.grid(row=2, column=1, padx=0, pady=2)
    panel2.grid_remove()

    rsa_cb = Checkbutton(panel1, text='RSA', bg='lightgray', variable=rsa_var, command=lambda: show_key_sig(1))
    dsa_elg_cb = Checkbutton(panel1, text='DSA/ElGamal', bg='lightgray', variable=dsa_var,
                             command=lambda: show_key_sig(2))
    rsa_cb.grid(row=0, column=0, sticky='nsew')
    dsa_elg_cb.grid(row=0, column=1, sticky='nsew')

    # ------------TAJNOST---------
    panel5 = Frame(frame, bg='lightgray', height=100)
    panel5.grid(row=6, column=0, sticky='nsew')

    panel6 = Frame(frame, bg='lightgray', height=100)
    panel6.grid(row=7, column=0, sticky='nsew')

    enc_lib = Label(panel5, bg='lightgray', text="Encrypt the message:")
    enc_lib.grid(row=0, column=0, padx=0, pady=2)

    en_var = BooleanVar()
    aes_var = BooleanVar()
    des3_var = BooleanVar()

    encrypt_xbox = Checkbutton(panel5, bg='lightgray', text=" ", variable=en_var, command=to_en_op)
    encrypt_xbox.grid(row=0, column=1, padx=0, pady=2)

    panel5.grid_remove()
    panel6.grid_remove()
    aes_cb = Checkbutton(panel6, text='AES', command=lambda: key_show_enc(1), variable=aes_var)
    des3_cb = Checkbutton(panel6, text='TripleDES', command=lambda: key_show_enc(2), variable=des3_var)
    aes_cb.grid(row=0, column=0, sticky='nsew')
    des3_cb.grid(row=0, column=1, sticky='nsew')

    # -----------MORE OPTIONS----------
    global panel9
    global zip_env
    global radix64_ven
    panel9 = Frame(frame, bg='lightgray', height=100)
    panel9.grid(row=10, column=0, sticky='nsew')

    zip_env = BooleanVar()
    radix64_ven = BooleanVar()
    zip_xbox = Checkbutton(panel9, bg='lightgray', text="zip", variable=zip_env)
    zip_xbox.grid(row=0, column=0, padx=0, pady=2)
    radix64_xbox = Checkbutton(panel9, bg='lightgray', text="radix-64", variable=radix64_ven)
    radix64_xbox.grid(row=0, column=1, padx=0, pady=2)

    # --------------TEXT----------------
    global panel10
    global text_input_text

    panel10 = Frame(frame, bg='lightgray', height=100)
    panel10.grid(row=11, column=0, sticky='nsew')
    text_label = Label(panel10, bg='lightgray', text="==========[ENTER TEXT]==========")
    text_label.grid(row=0, column=0, padx=0, pady=2)
    text_input_text = Text(panel10, width=50, height=15)
    text_input_text.grid(row=1, column=0, padx=0, pady=2)
    scrollbar = Scrollbar(panel10, command=text_input_text.yview)
    scrollbar.grid(row=1, column=1, sticky='ns')
    text_input_text.config(yscrollcommand=scrollbar.set)

    send_button = Button(panel10, text="send", width=20, command=send_message)
    send_button.grid(row=2, column=0, padx=0, pady=2)

    frame.bind("<Configure>", configure_scroll_region)
    scrollbar.config(command=scroll_canvas)

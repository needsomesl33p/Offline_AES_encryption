import json
from tkinter import StringVar, Frame, Widget, Label, Entry, Text, Button, OptionMenu, Radiobutton, END
from guiwizard import GUIWizard
from encoder import base64_encode, base64_decode, gen_iv
from typing import Tuple, List
from AEScryptor import KEY_SIZES, PADDING_STYLES, suits_prototype


def load_config(path: str) -> dict:
    with open(path, 'r') as file:
        return json.load(file)


def define_mostleft_panel(panel: Frame, radio_enc_type: StringVar) -> Tuple[List[Widget], dict]:
    widgets: List[Widget] = []
    packing_params = {'key': {'pady': (0, 30)},
                      'radiobutton': {'pady': (20, 0)}
                      }

    widgets.append(Label(panel, text='Key / Secret'))
    widgets.append(Entry(panel, width=35, name='key'))
    widgets.append(Label(panel, text='Plaintext'))
    widgets.append(Text(panel, width=45, height=30, name='plaintext'))
    widgets.append(Radiobutton(
        panel, variable=radio_enc_type, text='None', value='none'))
    widgets.append(Radiobutton(panel, variable=radio_enc_type,
                   text='Base64', value='base64'))
    return widgets, packing_params


def define_left_panel(panel: Frame, dropdown_key_var: StringVar) -> Tuple[List[Widget], dict]:
    widgets: List[Widget] = []
    packing_params = {'optionmenu': {'pady': (0, 85)},
                      'segment_size': {'pady': (0, 20)},
                      'mac_len': {'pady': (0, 20)},
                      'msg_len': {'pady': (0, 20)},
                      'initial_value': {'pady': (0, 20)},
                      'assoc_len': {'pady': (0, 20)}
                      }

    key_sizes: list = list(KEY_SIZES.keys())
    dropdown_key_var.set(key_sizes[0])

    widgets.append(Label(panel, text='Key size'))
    widgets.append(OptionMenu(panel, dropdown_key_var, *key_sizes))
    widgets.append(Label(panel, text='Segment size'))
    widgets.append(Entry(panel, width=35, name='segment_size'))
    widgets.append(Label(panel, text='MAC length'))
    widgets.append(Entry(panel, width=35, name='mac_len'))
    widgets.append(Label(panel, text='Message length'))
    widgets.append(Entry(panel, width=35, name='msg_len'))
    widgets.append(Label(panel, text='Initial value'))
    widgets.append(Entry(panel, width=35, name='initial_value'))
    widgets.append(Label(panel, text='Assoc length'))
    widgets.append(Entry(panel, width=35, name='assoc_len'))
    return widgets, packing_params


def define_right_panel(panel: Frame) -> Tuple[List[Widget], dict]:
    widgets: List[Widget] = []
    packing_params = {'nonce': {'pady': (0, 30)},
                      'ciphertext': {'pady': (0, 20)}
                      }

    widgets.append(Label(panel, text='IV / Nonce'))
    widgets.append(Entry(panel, width=35, name='nonce'))
    widgets.append(Label(panel, text='Ciphertext'))
    widgets.append(Text(panel, width=45, height=30, name='ciphertext'))
    widgets.append(Button(panel, text="Crypt", command=crypt,
                   name='crypt_button',  # state='disabled'
                          ))
    return widgets, packing_params


def define_mostright_panel(panel: Frame, dropdown_pad: StringVar, dropdown_mode: StringVar) -> Tuple[List[Widget], dict]:
    widgets: List[Widget] = []
    packing_params = {'button': {'pady': (20, 20)},
                      'optionmenu': {'pady': (0, 100)},
                      'optionmenu2': {'pady': (0, 270)},
                      }

    dropdown_pad.set(PADDING_STYLES[0])
    widgets.append(
        Button(panel, text="Generate IV / Nonce", command=gen_init_vector, state='disabled', name='iv_gen_button'))
    widgets.append(Label(panel, text='Padding'))
    widgets.append(OptionMenu(panel, dropdown_pad, *PADDING_STYLES))
    widgets.append(Label(panel, text='Block cipher mode of operation'))
    widgets.append(OptionMenu(panel, dropdown_mode, *config.keys()))
    widgets.append(Button(panel, text="Export Data", command=export_data))
    return widgets, packing_params


def gather_parameters():
    ui_params = {
        'key': bytes(gui.get_component_from_window('key').get(), encoding='utf-8'),
        'nonce': bytes(gui.get_component_from_window('nonce').get(), encoding='utf-8'),
        'key_size': dropdown_key_clicked.get(),
        'padding': dropdown_padding_clicked.get(),
        'op_mode': dropdown_mode_clicked.get(),
        'encoding': radio_enc_type.get(),
        'segment_size': bytes(gui.get_component_from_window('segment_size').get(), encoding='utf-8'),
        'mac_len': bytes(gui.get_component_from_window('mac_len').get(), encoding='utf-8'),
        'msg_len': bytes(gui.get_component_from_window('msg_len').get(), encoding='utf-8'),
        'initial_value': bytes(gui.get_component_from_window('initial_value').get(), encoding='utf-8'),
        'assoc_len': bytes(gui.get_component_from_window('assoc_len').get(), encoding='utf-8'),
    }

    return ui_params


def perform_encryption():
    plaintext: bytes = bytes(gui.get_component_from_window(
        'plaintext').get('1.0', 'end-1c'), encoding='utf-8')
    params: dict = gather_parameters()

    crpytor = suits_prototype[params['op_mode']](
        params['key'], plaintext, params['padding'], params['encoding'])
    ciphertext = crpytor.encrypt()
    cipher_textbox = gui.get_component_from_window('ciphertext')
    cipher_textbox.insert("1.0", ciphertext.decode())


def perform_decryption():
    ciphertext: bytes = bytes(gui.get_component_from_window(
        'ciphertext').get('1.0', 'end-1c'), encoding='utf-8')
    params: dict = gather_parameters()

    cryptor = suits_prototype[params['op_mode']](
        params['key'], plaintext, params['padding'], params['encoding'])


def gen_init_vector():
    nonce_text: Text = gui.get_component(2, 'nonce')
    init_vector: bytes = gen_iv(
        config[dropdown_mode_clicked.get()]['init_size'])
    b64_init_vector: bytes = base64_encode(init_vector).pop()
    nonce_text.delete(0, END)
    nonce_text.insert(0, b64_init_vector)


def crypt():
    # The first part, "1.0" means that the input should be read from line one, character zero (ie: the very first character).
    # END is an imported constant which is set to the string "end".
    plaintext: bytes = bytes(gui.get_component_from_window(
        'plaintext').get('1.0', 'end-1c'), encoding='utf-8')
    perform_encryption() if plaintext else perform_decryption()


def export_data():
    pass


def update_ui_properties(*args):
    mode = dropdown_mode_clicked.get()
    properties = config[mode].copy()
    del properties['id']
    del properties['init_size']
    gui.update_ui(properties)
    button = gui.get_component(3, 'iv_gen_button')
    button['state'] = 'normal'


def on_focus_out(event):
    plain_textbox = gui.get_component_from_window('plaintext')
    cipher_textbox = gui.get_component_from_window('ciphertext')
    if event.widget == plain_textbox or event.widget == cipher_textbox:
        if plain_textbox.get('1.0', 'end-1c') and not cipher_textbox.get('1.0', 'end-1c'):
            button = gui.get_component(2, 'crypt_button')
            button['state'] = 'normal'


config = load_config('./modes.json')
gui = GUIWizard('AES Encrpytion and Decryption', 1580, 760, 20, 20)
gui.create_panels(4)


dropdown_key_clicked = StringVar()
radio_enc_type = StringVar()
radio_enc_type.set('none')
dropdown_padding_clicked = StringVar()
dropdown_mode_clicked = StringVar()
dropdown_mode_clicked.trace_add('write', update_ui_properties)

plaintext = StringVar()


most_left_wigets, most_left_wiget_params = define_mostleft_panel(
    gui.panels[0], radio_enc_type)
left_widgets, letf_widget_params = define_left_panel(
    gui.panels[1], dropdown_key_clicked)
right_widgets, right_widget_params = define_right_panel(gui.panels[2])
most_right_wigets, most_right_wiget_params = define_mostright_panel(
    gui.panels[3], dropdown_padding_clicked, dropdown_mode_clicked)

gui.pack_on_panel(most_left_wigets, most_left_wiget_params)
gui.pack_on_panel(left_widgets, letf_widget_params)
gui.pack_on_panel(right_widgets, right_widget_params)
gui.pack_on_panel(most_right_wigets, most_right_wiget_params)

plain_textbox = gui.get_component_from_window('plaintext')
cipher_textbox = gui.get_component_from_window('ciphertext')


gui.pack_on_window()
gui.window.mainloop()

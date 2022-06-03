import json
from typing import Tuple, List
from tkinter import StringVar, Frame, Widget, Label, Entry, Text, Button, OptionMenu, Radiobutton, messagebox, END
from tkinter.filedialog import asksaveasfile
from guiwizard import GUIWizard, CryptInputException, SIVNonceException
from utils import base64_encode, gen_secret, sort_dict, load_config, convert_byte2string
from AEScryptor import KEY_SIZES, PADDING_STYLES, suits_prototype
from constants import INIT_UI_PARAMS, MOSTLEFT_PACKING_PARAMS, LEFT_PACKING_PARAMS, RIGHT_PACKING_PARAMS, MOSTRIGHT_PACKING_PARAMS


ENTRIES: List[str] = ['key', 'nonce', 'aad', 'mac', 'segment_size',
                      'mac_len', 'msg_len', 'initial_value', 'assoc_len']
TEXTS: List[str] = ['plaintext', 'ciphertext']


def get_textbox_value(component_name: str) -> str:
    return gui.get_component_from_window(component_name).get('1.0', 'end-1c')


def clear_textbox(components: list, component_type: str) -> None:
    prefix = 0 if component_type == 'entry' else '1.0'
    for entry_name in components:
        entry: Widget = gui.get_component_from_window(entry_name)
        entry.delete(prefix, END)


def define_mostleft_panel(panel: Frame) -> Tuple[List[Widget], dict]:
    widgets: List[Widget] = []
    widgets.append(Label(panel, text='Key / Secret'))
    widgets.append(Entry(panel, width=35, name='key'))
    widgets.append(Label(panel, text='IV / Nonce'))
    widgets.append(Entry(panel, width=35, name='nonce'))
    widgets.append(Label(panel, text='Plaintext'))
    widgets.append(Text(panel, width=45, height=30, name='plaintext'))
    widgets.append(Button(panel, text="Crypt", command=crypt,
                          name='crypt_button', state='disabled'))
    return widgets, MOSTLEFT_PACKING_PARAMS


def define_left_panel(panel: Frame, dropdown_key_var: StringVar, radio_enc_type: StringVar) -> Tuple[List[Widget], dict]:
    widgets: List[Widget] = []
    key_sizes: List[str] = list(KEY_SIZES.keys())
    dropdown_key_var.set(key_sizes[0])

    widgets.append(Label(panel, text='Key size'))
    widgets.append(OptionMenu(panel, dropdown_key_var, *key_sizes))
    widgets.append(Label(panel, text='Key / AAD encoding'))
    widgets.append(Radiobutton(
        panel, variable=radio_enc_type, text='None', value='none'))
    widgets.append(Radiobutton(panel, variable=radio_enc_type,
                   text='Base64', value='base64', name='encoding'))
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
    return widgets, LEFT_PACKING_PARAMS


def define_right_panel(panel: Frame) -> Tuple[List[Widget], dict]:
    widgets: List[Widget] = []

    widgets.append(Label(panel, text='Additional Authenticated Data (AAD)'))
    widgets.append(Entry(panel, width=35, name='aad'))
    widgets.append(Label(panel, text='Message Authentication Code/Tag (MAC) - Decrypt'))
    widgets.append(Entry(panel, width=35, name='mac'))
    widgets.append(Label(panel, text='Ciphertext'))
    widgets.append(Text(panel, width=45, height=30, name='ciphertext'))
    widgets.append(Button(panel, text="Clear panel", command=clear_panel,
                   name='clear_button'))
    return widgets, RIGHT_PACKING_PARAMS


def define_mostright_panel(panel: Frame, dropdown_pad: StringVar, dropdown_mode: StringVar) -> Tuple[List[Widget], dict]:
    widgets: List[Widget] = []
    dropdown_pad.set(PADDING_STYLES[0])
    widgets.append(Button(panel, text="Generate Key",
                   command=gen_key, name='key_gen_button'))
    widgets.append(
        Button(panel, text="Generate AAD", command=gen_aa_data, state='disabled', name='aad_gen_button'))
    widgets.append(Label(panel, text='Padding'))
    widgets.append(OptionMenu(panel, dropdown_pad, *PADDING_STYLES))
    widgets.append(Label(panel, text='Block cipher mode of operation'))
    widgets.append(OptionMenu(panel, dropdown_mode, *config.keys()))
    widgets.append(Button(panel, text="Export Data", command=export_data))
    return widgets, MOSTRIGHT_PACKING_PARAMS


def gather_necessary_params() -> dict:
    return {
        'key': bytes(gui.get_component_from_window('key').get(), encoding='utf-8'),
        'key_size': dropdown_key_clicked.get(),
        'padding': dropdown_padding_clicked.get(),
        'op_mode': dropdown_mode_clicked.get(),
        'encoding': radio_enc_type.get(),
    }


def gather_optional_params() -> dict:
    segment_size = gui.get_component_from_window('segment_size').get()
    mac_len = gui.get_component_from_window('mac_len').get()
    msg_len = gui.get_component_from_window('msg_len').get()
    initial_value = gui.get_component_from_window('initial_value').get()
    assoc_len = gui.get_component_from_window('assoc_len').get()

    return {
        'nonce': bytes(gui.get_component_from_window('nonce').get(), encoding='utf-8'),
        'segment_size': int(segment_size) if segment_size else '',
        'mac_len': int(mac_len) if mac_len else '',
        'msg_len': int(msg_len) if msg_len else '',
        'initial_value': int(initial_value) if initial_value else '',
        'assoc_len': int(assoc_len) if assoc_len else '',
        'aad': bytes(gui.get_component_from_window('aad').get(), encoding='utf-8'),
        'mac': bytes(gui.get_component_from_window('mac').get(), encoding='utf-8')
    }


def gather_parameters() -> Tuple[dict, dict]:
    necessary_params = gather_necessary_params()
    optional_params = gather_optional_params()
    sort_dict(optional_params)
    if not optional_params.get('nonce') and necessary_params['op_mode'] == 'SIV':
        raise SIVNonceException
    return necessary_params, optional_params


def perform_encryption():
    plaintext = bytes(get_textbox_value('plaintext'), encoding='utf-8')
    n_params, o_params = gather_parameters()
    op_mode: str = n_params['op_mode']
    crpytor = suits_prototype[op_mode](
        n_params['key'], plaintext, n_params['padding'], n_params['encoding'], **o_params)

    ciphertext, nonce, mac = crpytor.encrypt()
    if nonce:
        nonce_entry: Entry = gui.get_component_from_window('nonce')
        nonce_entry.insert(0, nonce.decode())
    if mac:
        mac_entry: Entry = gui.get_component_from_window('mac')
        mac_entry.insert(0, mac.decode())

    cipher_textbox: Text = gui.get_component_from_window('ciphertext')
    cipher_textbox.delete("1.0", END)
    cipher_textbox.insert("1.0", ciphertext.decode())


def perform_decryption():
    ciphertext = bytes(get_textbox_value('ciphertext'), encoding='utf-8')
    n_params, o_params = gather_parameters()
    op_mode: str = n_params['op_mode']
    cryptor = suits_prototype[op_mode](
        n_params['key'], ciphertext, n_params['padding'], n_params['encoding'], **o_params)

    plaintext = cryptor.decrypt()
    plaintext_textbox: Text = gui.get_component_from_window('plaintext')
    plaintext_textbox.delete("1.0", END)
    plaintext_textbox.insert("1.0", plaintext)


def crypt():
    try:
        plaintext: str = get_textbox_value('plaintext')
        ciphertext: str = get_textbox_value('ciphertext')

        if plaintext and ciphertext or (not plaintext and not ciphertext):
            raise CryptInputException
        if plaintext:
            perform_encryption()
        else:
            perform_decryption()

    except CryptInputException as ex:
        messagebox.showerror('Error', ex.message)

    except SIVNonceException as ex:
        messagebox.showerror('Error', ex.message)

    except ValueError as ex:
        messagebox.showerror('ValueError occured', str(ex))


def gen_key():
    radio_enc_type.set('base64')
    key_size: int = int(dropdown_key_clicked.get()) // 8
    key: bytes = gen_secret(key_size)
    b64_key: bytes = base64_encode(key)
    key_entry: Entry = gui.get_component_from_window('key')
    key_entry.delete(0, END)
    key_entry.insert(0, b64_key)


def gen_aa_data():
    radio_enc_type.set('base64')
    aad_entry: Entry = gui.get_component_from_window('aad')
    aad: bytes = gen_secret(
        config[dropdown_mode_clicked.get()]['init_size'])
    b64_aad: bytes = base64_encode(aad)
    aad_entry.delete(0, END)
    aad_entry.insert(0, b64_aad)


def clear_panel():
    clear_textbox(ENTRIES, 'entry')
    clear_textbox(TEXTS, 'text')


def export_data():
    file = asksaveasfile(initialfile='Untitled.txt', defaultextension='.txt', filetypes=[
                         ('JSON file', '*.json'), ('Text Documents', '*.txt')])
    params = gather_necessary_params()
    opt_params = gather_optional_params()
    params['ciphertext'] = get_textbox_value('ciphertext')
    params.update(opt_params)
    convert_byte2string(params)
    file.write(json.dumps(params, indent=4))
    file.close()
    messagebox.showinfo('File saving', 'Data export was successful!')


def update_ui_properties(*args):
    mode = dropdown_mode_clicked.get()
    properties = config[mode].copy()
    del properties['id']
    del properties['init_size']
    properties['crypt_button'] = {'state': 'normal'}
    properties['aad_gen_button'] = properties.get('aad')
    clear_textbox(ENTRIES[4:], 'entry')
    gui.update_ui(properties)


config = load_config('./modes.json')
gui = GUIWizard('AES Encrpytion and Decryption', 1580, 760, 20, 20)
gui.create_panels(4)


dropdown_key_clicked = StringVar()
radio_enc_type = StringVar()
radio_enc_type.set('none')
dropdown_padding_clicked = StringVar()
dropdown_mode_clicked = StringVar()
dropdown_mode_clicked.trace_add('write', update_ui_properties)


most_left_wigets, most_left_wiget_params = define_mostleft_panel(
    gui.panels[0])
left_widgets, letf_widget_params = define_left_panel(
    gui.panels[1], dropdown_key_clicked, radio_enc_type)
right_widgets, right_widget_params = define_right_panel(gui.panels[2])
most_right_wigets, most_right_wiget_params = define_mostright_panel(
    gui.panels[3], dropdown_padding_clicked, dropdown_mode_clicked)

gui.pack_on_panel(most_left_wigets, most_left_wiget_params)
gui.pack_on_panel(left_widgets, letf_widget_params)
gui.pack_on_panel(right_widgets, right_widget_params)
gui.pack_on_panel(most_right_wigets, most_right_wiget_params)
gui.update_ui(INIT_UI_PARAMS)

gui.pack_on_window()
gui.window.mainloop()

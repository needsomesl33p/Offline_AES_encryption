from tkinter import Tk, Canvas, PhotoImage, Frame, Widget
from typing import List


class GUIWizard:
    '''Defines a tkinter window and frames/panels to make the GUI development more transparent and easier.
    Think in panels and design your application according to them.
    Tear down your GUI to panels and put the widgets on.'''

    def __init__(self, window_title: str, window_width: int, window_height: int, padx: int, pady: int,
                 canvas_width=None, canvas_height=None, image_path=None) -> None:
        self.window = Tk()
        self.window.geometry(f'{window_width}x{window_height}')
        self.window.title(window_title)
        self.window.config(padx=padx, pady=pady)
        if image_path:
            self.canvas = Canvas(width=canvas_width,
                                 height=canvas_height, highlightthickness=0)
            self.image = PhotoImage(file=image_path)
            self.canvas.create_image(
                canvas_width/2, canvas_height/2, image=self.image)
            self.canvas.pack()

    @property
    def panels(self) -> List[Frame]:
        return self._panels

    @panels.setter
    def panels(self, value: List[Frame]) -> None:
        self._panels = value

    def get_packed_widget_name(self, branch_name: str):
        '''The full name contains the panel and a dot (.) or / and an exclamation mark (!). For example: .panel3.!label
        This method strips the panel section and the unnecessary characters from the widget name.'''
        split_chr = '!' if '!' in branch_name else '.'
        return branch_name.split(split_chr)[-1]

    def get_component(self, panel_number: int, component_name: str) -> Widget:
        '''Returns a Widget component. You need to provide the number of the panel where the specific component can be located.'''
        panel = self._panels[panel_number]
        components = panel.winfo_children()
        for item in components:
            name = self.get_packed_widget_name(str(item))
            if name == component_name:
                return item

    def get_component_from_window(self, componenet_name: str) -> Widget:
        '''Returns a Widget componenet from the window.'''
        panels_len = len(self._panels)
        for index in range(panels_len):
            item = self.get_component(index, componenet_name)
            if item:
                return item

    def update_ui(self, components: dict) -> None:
        '''Updates or configures the UI components with the specified parameters.'''
        for component_name, configs in components.items():
            component: Widget = self.get_component_from_window(component_name)
            component.configure(**configs)

    def create_panels(self, number: int) -> None:
        '''Create as many panels or frames as the number parameter gets.'''
        frames: List[Frame] = []
        for i in range(number):
            frame = Frame(self.window, name=f'panel{i}')
            frames.append(frame)
        self._panels = frames

    def pack_on_panel(self, wigets: List[Widget], packing_params: dict) -> None:
        '''Packs every Widget in the list on on the panel. 
        By the tkinter design, you need to provide the parent of the child widget, which is the panel.'''
        for item in wigets:
            name = self.get_packed_widget_name(str(item))
            if name in packing_params.keys():
                item.pack(**packing_params[name])
            else:
                item.pack()

    def pack_on_panel_same_config(self, wigets: List[Widget], kwargs: dict) -> None:
        '''Every Widget item will be configured with the same arguments or parameters.'''
        for item in wigets:
            item.pack(**kwargs)

    def pack_on_window(self) -> None:
        '''Packs the panels on the window. It starts the packing from a left and goes to the right.'''
        for frame in self._panels:
            frame.pack(side='left', expand=True)


class CryptInputException(Exception):
    '''Raised when no input data was provided in the en/decryption textboxes or both are filled.'''

    def __init__(self):
        self.message = '''No data was provided or both textbox are filled!
        Please fill only one textbox at least!'''

class SIVNonceException(Exception):
    '''Raised when Nonce entry is empty in case of SIV encryption mode.'''

    def __init__(self):
        self.message = '''Nonce cannot be empty when SIV mode is selected!'''
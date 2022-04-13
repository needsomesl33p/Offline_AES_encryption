from tkinter import Tk, Canvas, PhotoImage, Frame, Widget, Text
from typing import List, Tuple


class GUIWizard:
    '''Defines a tkinter window and frames/panels to make the GUI development more transparent and easier. 
    Think in panels and design your application according to them. Tear down your GUI to panels and put the widgets on.'''

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
        print(components)
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
        '''Packs every Widget in the list on on the panel. By the tkinter design, you need to provide the parent of the child wiget, which is the panel.'''
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


# class CustomText(Text):
#     def __init__(self, *args, **kwargs):
#         """A text widget that report on internal widget commands"""
#         Text.__init__(self, *args, **kwargs)

#         # create a proxy for the underlying widget
#         self._orig = self._w + "_orig"
#         self.tk.call("rename", self._w, self._orig)
#         self.tk.createcommand(self._w, self._proxy)

#     def _proxy(self, command, *args):
#         cmd = (self._orig, command) + args
#         result = self.tk.call(cmd)

#         if command in ("insert", "delete", "replace"):
#             self.event_generate("<<TextModified>>")

#         return result


# class CryptInputException(Exception):
#     '''Raised when no input data was provided in the en/decryption textboxes. Or when both of them filled out.'''

#     def __init__(self):
#         self.message = 'Concurrent operation detected or no data was provided! Please clear or fill only one textbox!'


# class IncorretKeySizeException(Exception):
#     '''Raised when the key size does not match the given key's length.'''

#     def __init__(self):
#         self.message = f'Key size does not match with key length. Follow the rules: KeySize - CharacterLength\n {list(KEY_SIZES.items())}.' \
#             '\nExcept SIV, for MODE_SIV it doubles to 32, 48, or 64 bytes.'

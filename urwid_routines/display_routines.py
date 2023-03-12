"""
Routines that use the urwid library to do interactive displays/UIs 
with the shell.
"""
import urwid
#------------------ routines for the menu-selection functionality---------
class menuButton(urwid.Button):
    button_left = urwid.Text('\N{BULLET}') # black circle    
    button_right = urwid.Text('')

class menuListBox(urwid.ListBox):
    """
    Intercept mouse scroll-up and scroll-down, and pass them off as
    up and down keys.   
    """
    def mouse_event(self, size, event, button, col, row, focus):
        if event == "mouse press":
            if button == 4.0:
                return super(menuListBox, self).keypress(size, 'up')
            elif button == 5.0:
                return super(menuListBox, self).keypress(size, 'down')
        return super(menuListBox, self).mouse_event(
            size, event, button, col, row, focus)

box_double = {
    'tlcorner' : chr(0x2554), 
    'tline' : chr(0x2550), 
    'lline' : chr(0x2551), 
    'trcorner' : chr(0x2557), 
    'blcorner' : chr(0x255a), 
    'rline' : chr(0x2551), 
    'bline' : chr(0x2550), 
    'brcorner' : chr(0x255d)}

box_single_bold = {
    'tlcorner' : chr(0x250f), 
    'tline' : chr(0x2501), 
    'lline' : chr(0x2503), 
    'trcorner' : chr(0x2513), 
    'blcorner' : chr(0x2517), 
    'rline' : chr(0x2503), 
    'bline' : chr(0x2501), 
    'brcorner' : chr(0x251b)}

class my_menu:
    def __init__(self, idxs=[], labs=[]):
        self.chosen_idx = None
        self.set_idxs(idxs)
        self.set_labs(labs)
        self.title = ''
    def set_idxs(self, idxs):
        self.idxs = idxs
    def set_labs(self, labs):
        self.labs = labs
    def exit_on_q(self, key):
        if key in ('q', 'Q'):
            raise urwid.ExitMainLoop()
    def menu(self, title):
        self.title = title
        body = []
        for idx, lab in zip(self.idxs, self.labs):
            button = menuButton(lab, on_press=self.item_chosen, user_data=idx)
            button._label._cursor_position = len(lab) + 1
            body.append(urwid.AttrMap(button, None, focus_map='reversed'))
        lbox = menuListBox(urwid.SimpleListWalker(body))
        return lbox
    def generate_main(self, user_message=''):
        padding_main  = urwid.Padding(self.menu(user_message), 
            left=2, right=2)
        line_main = urwid.LineBox(padding_main, 
            title=self.title, **box_single_bold)
        self.main = line_main
    def item_chosen(self, button, idx):
        self.chosen_idx = idx
        raise urwid.ExitMainLoop()

def labels_menu(labels, user_message='Select Item', 
    width=60., height=75., min_width=20, min_height=9):
    if not hasattr(labels, '__len__'):
        raise TypeError("input 'labels' must be a list-like object")
    if not isinstance(user_message, str):
        raise TypeError("user_message must be a str object")
    txt_header = urwid.Text("PYPASSMGR", align='center')
    fill_header = urwid.Filler(txt_header, valign='top')
    map_header = urwid.AttrMap(fill_header, 'reversed')
    
    indices = range(len(labels))
    mobj = my_menu(idxs=indices, labs=labels)
    mobj.generate_main(user_message)
    top = urwid.Overlay(mobj.main, urwid.SolidFill(u' '),
        align='center', width=('relative', width),
        valign='middle', height=('relative', height),
        min_width=min_width, min_height=min_height)
    pile_main = urwid.Pile([(1,map_header),top])
    loop = urwid.MainLoop(pile_main, palette=[('reversed','standout','')], unhandled_input=mobj.exit_on_q)
    loop.run()
    return mobj.chosen_idx

#------------- routines for display labels and decrypted password text---
def exit_on_q(key):
    if key in ('q','Q'):
        raise urwid.ExitMainLoop()

class scrolling_listbox(urwid.ListBox):
    """
    Intercept mouse scroll-up and scroll-down, and pass them off as
    up and down keys. Also space for 'pg-down' and 'b' for 'pg-up'
    """
    def keypress(self, size, key):
        if key == ' ':
            key = 'page down'
        if key == 'b':
            key = 'page up'
        return super().keypress(size, key)
    def mouse_event(self, size, event, button, col, row, focus):
        if event == "mouse press":
            if button == 4.0:
                return super().keypress(size, 'up')
            elif button == 5.0:
                return super().keypress(size, 'down')
        return super().mouse_event(size, event, button, col, row, focus)

def scroll_page(text_list):
    """
    Takes a list of urwid widgets and puts them into a scrollable list page,
    with footer.
    """
    if not isinstance(text_list,list):
        raise TypeError("Input 'text_list' must be a list")
    palette = [
        ('whiteonblue','white,bold','dark blue'),
        ('divbar','','dark gray'),
        ('labelstyle','white,bold','dark red'),
        ('alt_bg','','dark gray')]
    mainList = scrolling_listbox(urwid.SimpleListWalker(text_list))
    footerMessage = "Scroll with mouse, up/down keys; " + \
        "space/pg-down, b/pg-up.  Q/q to exit"
    footer = urwid.AttrMap(
        urwid.Text(footerMessage, align='center'),'whiteonblue')
    top = urwid.Frame(mainList, footer=footer)
    loop = urwid.MainLoop(top, palette, unhandled_input=exit_on_q)
    loop.run()

def display_labels_and_cipher(labels, pws_decr):
    if not isinstance(labels,list) or not isinstance(pws_decr,list):
        raise TypeError("Inputs 'labels' and 'pws_decr' must be lists")
    if len(labels) != len(pws_decr):
        raise ValueError("Inputs 'labels' and 'pws_decr' must be " + \
            "of the same length")
    txtList = []
    divObj = urwid.AttrMap(urwid.Divider(),'divbar')
    pwDispBegin = urwid.Text(chr(0x2501)*4 + chr(0x2513))
    pwDispEnd = urwid.Text(chr(0x2501)*4 + chr(0x251b))
    for label, pw_decr in zip(labels, pws_decr):
        txtList.append(divObj)
        txtList.append(urwid.Text(('labelstyle',label)))
        txtList.append(pwDispBegin)
        pwItemSplit = pw_decr.strip().split('\n')
        pwNewList = [" "*4 + chr(0x2503) + " " + item for item in pwItemSplit]
        pwText = '\n'.join(pwNewList)
        txtList.append(urwid.Text(pwText))
        txtList.append(pwDispEnd)
    scroll_page(txtList)

def display_labels_only(labels):
    if not isinstance(labels, list):
        raise TypeError("Input 'labels' must be a list")
    txtList = []
    idx_max_chars = len(str(len(labels)))
    for k0, label in enumerate(labels):
        item_list = []
        for k1, line in enumerate(label.split('\n')):
            if k1==0:
                item_list.append("{{:>{:d}d}}: {:s}".format(idx_max_chars,line).format(k0))
            else:
                item_list.append(" "*(idx_max_chars+2) + line)
        item_entry = '\n'.join(item_list)
        if k0%2 == 0:
            txtList.append(urwid.Text(item_entry))
        else:
            txtList.append(urwid.AttrMap(urwid.Text(item_entry),'alt_bg'))
    scroll_page(txtList)

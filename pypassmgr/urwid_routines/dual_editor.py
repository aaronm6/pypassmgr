import urwid
from itertools import zip_longest

box_in_focus = {
    'tlcorner' : chr(0x2554), 
    'tline' : chr(0x2550), 
    'lline' : chr(0x2551), 
    'trcorner' : chr(0x2557), 
    'blcorner' : chr(0x255a), 
    'rline' : chr(0x2551), 
    'bline' : chr(0x2550), 
    'brcorner' : chr(0x255d)}
box_out_of_focus = {
    'tlcorner' : chr(0x22c5), 
    'tline' : chr(0x22c5), 
    'lline' : chr(0x22c5), 
    'trcorner' : chr(0x22c5), 
    'blcorner' : chr(0x22c5), 
    'rline' : chr(0x22c5), 
    'bline' : chr(0x22c5), 
    'brcorner' : chr(0x22c5)}
box_footer = {
    'tlcorner' : chr(0x250f), 
    'tline' : chr(0x2501), 
    'lline' : chr(0x2503), 
    'trcorner' : chr(0x2513), 
    'blcorner' : chr(0x2517), 
    'rline' : chr(0x2503), 
    'bline' : chr(0x2501), 
    'brcorner' : chr(0x251b)}

class screen_keys:
    def __init__(self):
        self.screen = urwid.raw_display.Screen()
        self.set_undefined = ['undefined']*5
        self.orig_settings = None
    def __enter__(self):
        self.orig_settings = self.screen.tty_signal_keys(*self.set_undefined)
        return self
    def __exit__(self, thetype, thevalue, traceback):
        self.screen.tty_signal_keys(*self.orig_settings)

class my_edit(urwid.Edit):
    # _clipboard is a class var so one can copy from one editor and paste 
    # into another
    _clipboard = ''
    def __init__(self, *args, **kwargs):
        self.orig_text = kwargs['edit_text']
        # flag _cp_append: true means cuts append to clipboard, 
        #                  false means cuts reset clipboard
        self._cp_append = False 
        self.prev_text = ''
        super(my_edit, self).__init__(*args, **kwargs)
    def keypress(self, size, key):
        if key == 'ctrl z':
            self.edit_text = self.orig_text
            return
        elif key == 'ctrl k':
            self.cut_line(size)
            return
        elif key == 'ctrl u':
            self.paste_text()
            return
        elif key == 'meta b':   # meta-left
            current_pos = max(0, self.edit_pos-1)
            nearest_space = self.edit_text.rfind(' ', 0, current_pos)
            nearest_newline = self.edit_text.rfind('\n', 0, current_pos)
            nearest_wordbreak = max(nearest_space, nearest_newline)
            self.edit_pos = nearest_wordbreak + 1
            return
        elif key == 'meta f':   # meta-right
            current_pos = self.edit_pos
            nearest_space = self.edit_text.find(' ', current_pos+1)
            if nearest_space == -1:
                nearest_space = len(self.edit_text)
            nearest_newline = self.edit_text.find('\n', current_pos+1)
            if nearest_newline == -1:
                nearest_newline = len(self.edit_text)
            nearest_wordbreak = min(nearest_space, nearest_newline)
            self.edit_pos = nearest_wordbreak
            return
        else:
            if key == 'ctrl a':
                key = 'home'
            elif key == 'ctrl e':
                key = 'end'
            return super(my_edit, self).keypress(size, key)
    def cut_line(self, size):
        text_str = self.edit_text
        text_lines = text_str.split('\n')
        # next line ensures proper cursor behavior if cutting last line 
        # and it doesn't have a trailing \n
        if text_lines[-1]:
            text_lines.append('')
        # get_cursor_coords returns (n, m), n=col, m=row 
        # (indexed from 0, not 1)
        current_row = self.get_cursor_coords(size)[1]
        if self._cp_append:
            my_edit._clipboard += text_lines.pop(current_row) + '\n'
        else:
            my_edit._clipboard = text_lines.pop(current_row) + '\n'
        self.edit_text = '\n'.join(text_lines)
        self._cp_append = True
    def paste_text(self):
        text_str = self.edit_text
        cursor_pos = self.edit_pos
        new_text = text_str[:cursor_pos] + my_edit._clipboard + \
            text_str[cursor_pos:]
        self.edit_text = new_text
        self.edit_pos += len(my_edit._clipboard)
        self._cp_append = False

class editor_commands:
    def __init__(self):
        self.commands = []
        self.descr = []
        self.txt_list = []
    def add_command(self,command,descr):
        self.commands.append(command)
        self.descr.append(descr)
    def compile_obj(self):
        i_commands = [iter(self.commands)]*2
        i_descr = [iter(self.descr)]*2
        for command1, command2, descr1, descr2 in \
            zip_longest(*i_commands, *i_descr):
            txt_command1 = urwid.Text(('reverse', command1))
            txt_descr1 = urwid.Text(descr1)
            line1 = urwid.Columns([('pack', txt_command1),txt_descr1], 
                dividechars=1)
            if command2:
                txt_command2 = urwid.Text(('reverse', command2))
                txt_descr2 = urwid.Text(descr2)
                line2 = urwid.Columns([('pack', txt_command2),txt_descr2], 
                    dividechars=1)
            else:
                line2 = urwid.Columns([('pack', urwid.Text(' ')), 
                    urwid.Text(' ')], dividechars=1)
            pile = urwid.Pile([line1, line2])
            self.txt_list.append(pile)

class editor_columns(urwid.Columns):
    def __init__(self, *args, **kwargs):
        self.save_status = False
        self.timeout_status = False
        super(editor_columns, self).__init__(*args, **kwargs)
    def keypress(self, size, key):
        if key in ('ctrl t','tab'):
            self.focus_position = (self.focus_position + 1) % 2
        else:
            return super(editor_columns, self).keypress(size, key)
    @property
    def focus_position(self):
        """
        index of child widget in focus. Raises :exc:`IndexError` if read when
        Columns is empty, or when set to an invalid index.
        """
        return urwid.Columns.focus_position.fget(self)
    @focus_position.setter
    def focus_position(self, position):
        for item in self.widget_list:
            w_line = item.contents[1][0].original_widget
            w_ttl = w_line.title_widget
            orig_title = w_ttl.get_text()
            w_line.__init__(w_line.original_widget, **box_out_of_focus)
            w_ttl = w_line.title_widget
            w_ttl.set_text(orig_title[0])
        urwid.Columns.focus_position.fset(self, position)
        w_line = \
            self.widget_list[position].contents[1][0].original_widget
            #self._get_widget_list()[position].contents[1][0].original_widget
        w_ttl = w_line.title_widget
        orig_title = w_ttl.get_text()
        w_line.__init__(w_line.original_widget, **box_in_focus)
        w_ttl = w_line.title_widget
        w_ttl.set_text(('reverse',orig_title[0]))
    """
    def _set_focus_position(self, position):
        #for item in self._get_widget_list():
        for item in self.widget_list:
            w_line = item.contents[1][0].original_widget
            w_ttl = w_line.title_widget
            orig_title = w_ttl.get_text()
            w_line.__init__(w_line.original_widget, **box_out_of_focus)
            w_ttl = w_line.title_widget
            w_ttl.set_text(orig_title[0])
        super(editor_columns, self)._set_focus_position(position)
        w_line = \
            self.widget_list[position].contents[1][0].original_widget
            #self._get_widget_list()[position].contents[1][0].original_widget
        w_ttl = w_line.title_widget
        orig_title = w_ttl.get_text()
        w_line.__init__(w_line.original_widget, **box_in_focus)
        w_ttl = w_line.title_widget
        w_ttl.set_text(('reverse',orig_title[0]))
    def _get_focus_position(self):
        return super(editor_columns, self)._get_focus_position()
    """
    '''
    focus_position = property(_get_focus_position, _set_focus_position, 
        doc="""
        index of child widget in focus. Raises :exc:`IndexError` if read when
        Columns is empty, or when set to an invalid index.
        """
    '''

class confirmbox_handler:
    """
    This is a wrapper for the full layout, but it overlays a "confirm 
    box" when the user wishes to save or cancel, asking the user to 
    confirm their selection.  This class handles also the creation and 
    running of the main loop.  "cancel" and "save" commands (or any 
    other commands which would require confirmation) are handled here 
    with a class function which is passed to the main loop's "unhandled 
    input" method.
    
    constructor input "exit_options" must be a dict object, where each
    key is a desired possible exit key, and the associated value 
    is the message that will be displayed in the confirm box.
    """
    def __init__(self, o_widget, palette, exit_options):
        # o_widget is the original widget, before a box is overlaid
        self.o_widget = o_widget 
        self.in_conf_box = False # True if there is a confirm-box overlaid
        self.exit_command = ''
        self.exit_options = exit_options
        self.loop = urwid.MainLoop(self.o_widget, palette, unhandled_input=self.unhandled_input)
    def run(self):
        self.loop.run()
    def unhandled_input(self, key):
        if not self.in_conf_box:
            if key in self.exit_options:
                self.exit_command = key
                self.create_box_and_overlay(message=self.exit_options[key])
        else:
            if key in ('y', 'Y'):
                raise urwid.ExitMainLoop()
            else:
                self.remove_box()
            #if key in ('n', 'N'):
            #    self.remove_box()
    def create_box_and_overlay(self, message='confirm?'):
        confmsg = urwid.Text(message, align='center')
        YNtext = urwid.Text('Y / N', align='center')
        conftxt = urwid.Pile([confmsg, YNtext])
        confFiller = urwid.Filler(conftxt)
        Lbox = urwid.LineBox(confFiller, **box_in_focus)
        conf_box = urwid.Overlay(Lbox,
            self.o_widget,
            align='center', width=('relative',35),
            valign='middle', height=('relative',35))
        self.loop.widget = conf_box
        self.in_conf_box = True
    def remove_box(self):
        self.exit_command = ''
        self.in_conf_box = False
        self.loop.widget = self.o_widget

def dual_editor(init_txt_unenc='', init_txt_enc=''):
    """
    Open side-by-side text editors, unencrypted label on the left, 
    encrypted text on the right.
    The editors get pre-populated with the given input text.
    No text is encrypted or decrypted here; these are simply the 
    intended usage in pypassmgr.
    
    Returns:
        exit status: 0 (new text was saved) or 1 (problem or editing 
            was canceled)
        new unencrypted text: plaintext of the entry label (intended 
            to remain plaintext)
        new encrypted text: plaintext of the entry contents, that is 
            intended to laber be encrypted (by the calling routine).
    """
    palette = [
        ('reverse','standout',''),]
    
    map_header = urwid.AttrMap(
        urwid.Filler(urwid.Text("PYPASSMGR", align='center'), valign='top'),
        'reverse')
    
    fill_instructions = urwid.Filler(
        urwid.Text("Edit entry details; save or cancel to continue.",
        align='center'))
    
    edit1 = my_edit('',multiline=True, edit_text=init_txt_unenc)
    fill_main1 = urwid.Filler(edit1, valign='top',top=0)
    line_main1 = urwid.LineBox(fill_main1, title='UNencrypted Label')
    padding_main1 = urwid.Padding(line_main1, left=1, right=1)
    overlay_main1 = urwid.Overlay(padding_main1, urwid.SolidFill(u' '),
        align='left', width=('relative',100), valign='middle', 
        height=('relative',100))
    
    edit2 = my_edit('',multiline=True, edit_text=init_txt_enc)
    fill_main2 = urwid.Filler(edit2, valign='top',top=0)
    line_main2 = urwid.LineBox(fill_main2, title='Encrypted Text')
    padding_main2 = urwid.Padding(line_main2, left=1, right=1)
    overlay_main2 = urwid.Overlay(padding_main2, urwid.SolidFill(u' '),
        align='left', width=('relative',100), valign='middle', 
        height=('relative',100))
    
    columns_editors = editor_columns(
        [('weight',40,overlay_main1),('weight',60,overlay_main2)], 
        dividechars=1)
    
    cmnds = editor_commands()
    cmnds.add_command('^T','Toggle Box')
    cmnds.add_command('^Z','Reset Text')
    cmnds.add_command('^K', 'Cut Line')
    cmnds.add_command('^U', 'Uncut Line')
    cmnds.add_command('^C','Cancel')
    cmnds.add_command('^S','Save')
    cmnds.add_command('^A','Home')
    cmnds.add_command('^E','End')
    
    cmnds.compile_obj()
    cols_footer = urwid.Columns(cmnds.txt_list, dividechars=1)
    
    fill_footer = urwid.Filler(cols_footer, valign='bottom')
    line_footer = urwid.LineBox(fill_footer, **box_footer)
    div_footer = urwid.Divider(div_char=chr(0x2501))
    fill_div_footer = urwid.Filler(div_footer, valign='bottom')
    pile = urwid.Pile(
        [(1,map_header),(3,fill_instructions),
        columns_editors,(1,fill_div_footer), (2,fill_footer)])
    flag_timeout = False
    world = confirmbox_handler(pile, palette,
        {'ctrl c':'CONFIRM CANCEL?','ctrl s':'CONFIRM SAVE?'})
    with screen_keys():
        world.run()
    if world.exit_command == 'ctrl s':
        exit_status = 0
        new_txt_unenc = edit1.edit_text
        new_txt_enc   = edit2.edit_text
    else:
        exit_status = 1
        new_txt_unenc = 'na'
        new_txt_enc   = 'na'
    return exit_status, new_txt_unenc, new_txt_enc

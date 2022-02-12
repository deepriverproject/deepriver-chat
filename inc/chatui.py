import locale
import curses
locale.setlocale(locale.LC_ALL,"")

class ScreenNotInitialized(Exception):
    pass

class ChatUI_Log:
    def __init__(self, screen):
        self._screen = screen
        self.HEIGHT, self.WIDTH = self._screen.getmaxyx()
        self._screen.border("|","|","-","-","+","+","+","+")
        self._screen.refresh()

        self._full_log = []
        if curses.has_colors():
            curses.start_color()

            # Normie color
            curses.init_pair(1, curses.COLOR_WHITE, curses.COLOR_BLACK)
            
            # Client-side message color
            curses.init_pair(2, curses.COLOR_BLACK, curses.COLOR_WHITE)
            
            # Server-side success
            curses.init_pair(3, curses.COLOR_BLACK, curses.COLOR_GREEN)
    
            # Server-side fail
            curses.init_pair(4, curses.COLOR_BLACK, curses.COLOR_RED)

    def _clear_log(self):
        self._full_log = []
        self._refresh_log()

    def _refresh_log(self):
        self._screen.clear()
        self._screen.border("|","|","-","-","+","+","+","+")
        y = 1

        for item in self._full_log:
            if curses.has_colors():
                self._screen.addstr(y,1,item['text'], curses.color_pair(item['color']))
            else:
                self._screen.addstr(y,1,item['text'])
            y += 1
        self._screen.refresh()

    def update_log(self, item: str, color = 1):
        self._full_log.append({'text': item, "color": color})

        tmp_log = []
        for item in self._full_log:
            while len(item['text']) > self.WIDTH - 2:
                tmp_log.append({'text': item['text'][0:self.WIDTH - 2], "color": item['color']})
                item['text'] = item['text'][self.WIDTH - 2::]
            if len(item['text']) > 0:
                tmp_log.append(item)
        
        if len(tmp_log) > self.HEIGHT - 2:
            diff = len(tmp_log) - (self.HEIGHT - 2)
            tmp_log = tmp_log[diff::]

        self._full_log = tmp_log
        self._refresh_log()
    
    def on_active(self):
        self._refresh_log()
    
    def on_deactive(self):
        pass

    def on_keypress(self, key):
        pass

class ChatUI_Input:
    def __init__(self, screen, parent_screen):
        self._strscr = parent_screen
        self._screen = screen

        self._input_y = parent_screen.getmaxyx()[0] - 2

        self._screen.border("|","|","-","-","+","+","+","+")
        self._screen.refresh()
        self.HEIGHT, self.WIDTH = self._screen.getmaxyx()

        self._full_input = ""
        self._cursor_pos = 1
    
    def clear_input(self):
        self._cursor_pos = 1
        self._full_input = ""

        self._screen.clear()
        self._screen.border("|","|","-","-","+","+","+","+")
        self._strscr.move(self._input_y, self._cursor_pos)
        self._screen.refresh()

    def _refresh_input(self):
        self._screen.clear()
        self._screen.border("|","|","-","-","+","+","+","+")
        if len(self._full_input) > self.WIDTH - 2:
            offset = len(self._full_input) - (self.WIDTH - 2)
            self._screen.addstr(1,1, self._full_input[offset::])
        else:
            self._screen.addstr(1,1, self._full_input)
        self._strscr.move(self._input_y, self._cursor_pos)
        self._screen.refresh()
    
    def get_input(self):
        return self._full_input

    def on_active(self):
        self._strscr.move(self._input_y, self._cursor_pos)
        self._strscr.refresh()
    
    def on_deactive(self):
        pass

    def on_keypress(self, key):
        if type(key) == str and len(key) > 1:
            if key == "KEY_DC":
                self.clear_input()
        else:
            # DELETE key
            if ord(key) == 8:
                self._full_input = self._full_input[:-1]
                if len(self._full_input) > 0:
                    self._cursor_pos -= 1 if len(self._full_input) < self.WIDTH - 3 else 0
                else:
                    self._cursor_pos = 1
                self._refresh_input()
            elif type(key) == str:
                self._cursor_pos += 1 if len(self._full_input) < self.WIDTH - 3 else 0
                self._full_input += key
                self._refresh_input()
            
class ChatUI:
    def __init__(self, _input_callback = None):
        self._strscr = None
        self._logscr = None
        self._inputscr = None
        self._input_callback = _input_callback

        self._active_win = None
    
    def init(self, strscr):
        self._strscr = strscr
        self.HEIGHT, self.WIDTH = self._strscr.getmaxyx()
        self._build_strscr()
        
        log_h = self.HEIGHT - 2

        self._log_scr = ChatUI_Log(self._strscr.derwin(log_h, self.WIDTH, 0,0))
        self._input_scr = ChatUI_Input(self._strscr.derwin(3, self.WIDTH,log_h -1, 0), self._strscr)

        self._active_win = self._input_scr
        self._active_win.on_active()

        while True:
            pressed_key = self._strscr.getkey()

            if type(pressed_key) == str and len(pressed_key) > 1:
                self._active_win.on_keypress(pressed_key)
                continue

            # CTRL + C
            if ord(pressed_key) == 3:
                break
            
            # ENTER
            if ord(pressed_key) == 10:
                if len(inp := self._input_scr.get_input()) > 0:
                    if self._input_callback:
                        self._input_callback(inp)
                    self._input_scr.clear_input()
                continue

            self._active_win.on_keypress(pressed_key)
    
    def add_to_log(self, item, color = 1):
        self._log_scr.update_log(item, color)
        self._input_scr._refresh_input()

    def set_input_callback(self, callback):
        self._input_callback = callback

    def _build_strscr(self):
        if not self._strscr:
            raise ScreenNotInitialized("Main screen was not initialized.")
        self._strscr.clear()
        self._strscr.refresh()
        return True
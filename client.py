import curses, re
from inc.chatui import ChatUI

cui = ChatUI()

def on_input(inp):
    if inp[0] == '/':
        if len(inp) < 2:
            return
        cui.add_to_log(f"Command detected: {inp.split(' ')[0][1::]}", color=2)
        return
    cui.add_to_log(inp)

if __name__ == "__main__":
    cui.set_input_callback(on_input)
    curses.wrapper(cui.init)
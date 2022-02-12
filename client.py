import curses, re
from inc.chatui import ChatUI

cui = ChatUI()

def on_input(inp):
    if inp[0] == '/':
        if len(inp) < 2:
            return
        
        cmd = inp[1::].split(" ")
        
        if cmd[0] == 'clear':
            cui.clear_log()
            return
        cui.add_to_log(f"Invalid command: {cmd[0]}", color=2)
        return
    cui.add_to_log(inp)

if __name__ == "__main__":
    cui.set_input_callback(on_input)
    curses.wrapper(cui.init)
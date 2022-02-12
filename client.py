import curses
from inc.chatui import ChatUI

if __name__ == "__main__":
    cui = ChatUI()
    curses.wrapper(cui.init)
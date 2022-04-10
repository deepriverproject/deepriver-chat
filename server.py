from inc.deepriver_server import DeepRiver_Server
import threading

if __name__ == '__main__':
    d = DeepRiver_Server()
    threading.Thread(target=d.start).start()
    try:
        while True:
            continue
    except KeyboardInterrupt:
        d.stop()
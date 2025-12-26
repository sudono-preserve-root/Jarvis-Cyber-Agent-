import socket
import threading
import logging

class Honeypot:
    # FIX: Added 'bind_port' here to match main.py
    def __init__(self, bind_port=8080, bind_ip='0.0.0.0'):
        self.bind_port = bind_port
        self.bind_ip = bind_ip
        self.server_socket = None
        self.running = False
        self.thread = None
        self.logger = logging.getLogger("Sentinel.Honeypot")

    def start(self):
        """Starts the honeypot listener in a separate thread."""
        self.running = True
        self.thread = threading.Thread(target=self._listen, daemon=True)
        self.thread.start()

    def stop(self):
        """Stops the listener and closes the socket."""
        self.running = False
        if self.server_socket:
            try:
                self.server_socket.close() 
            except Exception as e:
                self.logger.error(f"Error closing socket: {e}")

    def _listen(self):
        """Internal listener loop."""
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind((self.bind_ip, self.bind_port))
            self.server_socket.listen(5)
            self.logger.info(f"Listener active on {self.bind_ip}:{self.bind_port}")

            while self.running:
                try:
                    client, addr = self.server_socket.accept()
                    self.logger.warning(f"INTRUSION DETECTED: Connection from {addr[0]}:{addr[1]}")
                    client.close()
                except OSError:
                    break
                except Exception as e:
                    self.logger.error(f"Listener error: {e}")

        except Exception as e:
            self.logger.critical(f"Failed to bind honeypot: {e}")
        finally:
            if self.server_socket:
                self.server_socket.close()
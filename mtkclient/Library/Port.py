import os
import sys
import logging
import time
from binascii import hexlify
from struct import pack, unpack
from mtkclient.Library.gui_utils import LogBase, logsetup

class Port(metaclass=LogBase):
    def __init__(self, mtk, portconfig, serialportname=None, loglevel=logging.INFO):
        self.__logger, self.info, self.debug, self.warning, self.error = logsetup(self, self.__logger, loglevel, mtk.config.gui)
        self.config = mtk.config
        self.mtk = mtk
        self.fd = None
        self.connected = False
        fd_env = os.environ.get("TERMUX_USB_FD")
        if fd_env:
            self.fd = int(fd_env)
            self.info("Using Termux-USB FD Sniper Mode")
            for _ in range(20000):
                try:
                    os.write(self.fd, b"\x00")
                    self.connected = True
                    break
                except:
                    continue
        self.pid = 0x0003

    def usbwrite(self, data, timeout=1000):
        try:
            os.write(self.fd, data)
            return len(data)
        except:
            return 0

    def usbread(self, size, timeout=1000, maxtimeout=None):
        try:
            return os.read(self.fd, size)
        except:
            return b""

    def rdword(self):
        try:
            return unpack(">I", self.usbread(4))[0]
        except:
            return 0

    def rword(self):
        try:
            return unpack("<I", self.usbread(4))[0]
        except:
            return 0

    def rbyte(self):
        return self.usbread(1)

    def close(self):
        self.connected = False

    def run_handshake(self):
        startcmd = b"\xa0\x0a\x50\x05"
        for byte in startcmd:
            self.usbwrite(bytes([byte]))
            echo = self.usbread(1)
            if not echo or echo[0] != (~byte & 0xFF):
                return False
        self.info("Device detected :)")
        return True

    def handshake(self, maxtries=None, loop=0):
        if self.connected and self.run_handshake():
            return True
        return False

    def echo(self, data):
        if isinstance(data, int): data = pack(">I", data)
        if isinstance(data, bytes): data = [data]
        for val in data:
            self.usbwrite(val)
            if val != self.usbread(len(val)): return False
        return True

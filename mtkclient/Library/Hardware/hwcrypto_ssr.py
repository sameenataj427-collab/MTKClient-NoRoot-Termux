#!/usr/bin/python3
# -*- coding: utf-8 -*-
# (c) B.Kerler 2018-2025 GPLv3 License

# SSR = Scalable Security Root

import logging
import struct
from enum import Enum
from typing import Callable, Optional, Tuple
import time

from Crypto.Util.number import long_to_bytes

from mtkclient.Library.Hardware import RegisterMap
from mtkclient.Library.gui_utils import LogBase, logsetup

ecc_domain_p256 = [
    0xd835c65a, 0xe7933aaa, 0x55bdebb3, 0xbc869876,
    0xb0061d65, 0xf6b053cc, 0x3e3cce3b, 0x4b60d227
]

ecc_domain_p384 = [
    0xa72f31b3, 0xe4e73ee2, 0x6b058e98, 0x192df8e3,
    0x6e9c1d18, 0x124181fe, 0x8f081403, 0x5a871350,
    0x8d3956c6, 0x9dd12e8a, 0xedc8852a, 0xef2aecd3
]

def genmask(h: int, l: int) -> int:
    if not (0 <= l <= h <= 63):
        raise ValueError("GENMASK: must satisfy 0 <= l <= h <= 63 (64-bit macro)")
    width = h - l + 1
    return ((1 << width) - 1) << l


SSR_KDF_HKDF_CMD_START = 0
SSR_KDF_HKDF_CMD_FIXED = (1 << 5 | 1 << 1)
SSR_KDF_HKDF_CMD_NO_SALT = 1 << 3
SSR_KDF_HKDF_CMD_IKM_LEN = genmask(15, 8)
SSR_KDF_HKDF_CMD_SALT_LEN = genmask(23, 16)
SSR_KDF_HKDF_CMD_INFO_LEN = genmask(31, 24)
SSR_KDF_HKDF_STS_ERR = genmask(4, 0)
SSR_CLK_RNG = (1 << 0)
SSR_CLK_CCC = (1 << 8)
SSR_CLK_KDF = (1 << 16)
SSR_CLK_PKA = (1 << 24)
SSR_KDF_CMAC_ST_DONE = 0x80000000
SSR_INIT_MAGIC1 = 0x35003400
SSR_INIT_MAGIC2 = 0x06BF3701
SSR_TIMEOUT = 5000

class RpmbType(Enum):
    RPMB = 0
    FDE = 1
    TEE = 2
    AES_IMG_ENC = 3
    AES_CUSTOM = 4
    MOTOROLA = 5
    BASE_KEY = 6
    CUSTOM1 = 7
    CUSTOM2 = 8


class KDFType(Enum):
    SW_KEY = 0
    INT_REG0 = 2
    FUSE_KDR = 4


class AESType(Enum):
    AES_256 = 0
    AES_128 = 1
    AES_192 = 2


class AESKeyLen(Enum):
    AES_256 = 0x20
    AES_128 = 0x10
    AES_192 = 0x18


class PKA_ECC(Enum):
    ECC_CURVE_NIST_P256 = 0
    ECC_CURVE_NIST_P384 = 4


class PKA_RSA(Enum):
    RSA_1024 = 0
    RSA_2048 = 1
    RSA_3072 = 2
    RSA_4096 = 3


class PKA_OP(Enum):
    RSA_MODEXP = 2
    ECC_GENKEY = 5
    ECC_SIGN_P256 = 6
    ECC_SIGN_P384 = 7
    ECC_VERIFY_P256 = 8
    ECC_VERIFY_P384 = 9

SSR_PKA_ECC_P256_WORDS      =8
SSR_PKA_ECC_P384_WORDS      =12
PKA_RSA_SIGN_TIMEOUT        =10000


class CCC_SHAType(Enum):
    SHA256 = 0
    SHA384 = 6

clk_regs = {
    "CFG_UPDATE2" : 0xC,
    "CFG_16_SET" : 0x114,
    "CFG_16_CLR" : 0x118,
    "CFG_17_SET" : 0x124,
    "CFG_17_CLR" : 0x128,
}

ccc_regs = {
    "BASE": 0,
    "SHA_JOB_ID": 0x2C,
    "SHA_OUT": 0x34,
    "QUEUE_AVAILABLE": 0x100,
    "QUEUE": 0x104,
    "HW_INIT_CFG0": 0x2AC,
    "HW_INIT_CFG1": 0x2B0,
    "SKIP_KS_INIT": 0x2D4,
    "SSR_BOOT": 0x2F8
}

kdf_regs = {
    "SSR_BASE": 0x0000,
    "SSR_KDF_CMAC_OUT0": 0x000,
    "SSR_KDF_CMAC_OUT1": 0x004,
    "SSR_KDF_CMAC_OUT2": 0x008,
    "SSR_KDF_CMAC_OUT3": 0x00C,
    "SSR_KDF_CMAC_OUT4": 0x010,
    "SSR_KDF_CMAC_OUT5": 0x014,
    "SSR_KDF_CMAC_OUT6": 0x018,
    "SSR_KDF_CMAC_OUT7": 0x01C,
    "SSR_KDF_CMAC_OUT8": 0x020,
    "SSR_KDF_CMAC_OUT9": 0x024,
    "SSR_KDF_CMAC_OUT10": 0x028,
    "SSR_KDF_CMAC_OUT11": 0x02C,
    "SSR_KDF_CMAC_OUT12": 0x030,
    "SSR_KDF_CMAC_OUT13": 0x034,
    "SSR_KDF_CMAC_OUT14": 0x038,
    "SSR_KDF_CMAC_OUT15": 0x03C,
    "SSR_KDF_CMAC_FIN0": 0x040,
    "SSR_KDF_CMAC_FIN1": 0x044,
    "SSR_KDF_CMAC_FIN2": 0x048,
    "SSR_KDF_CMAC_FIN3": 0x04C,
    "SSR_KDF_CMAC_FIN4": 0x050,
    "SSR_KDF_CMAC_FIN5": 0x054,
    "SSR_KDF_CMAC_FIN6": 0x058,
    "SSR_KDF_CMAC_FIN7": 0x05C,
    "SSR_KDF_CMAC_FIN8": 0x060,
    "SSR_KDF_CMAC_FIN9": 0x064,
    "SSR_KDF_CMAC_FIN10": 0x068,
    "SSR_KDF_CMAC_FIN11": 0x06C,
    "SSR_KDF_CMAC_FIN12": 0x070,
    "SSR_KDF_CMAC_FIN13": 0x074,
    "SSR_KDF_CMAC_FIN14": 0x078,
    "SSR_KDF_CMAC_FIN15": 0x07C,
    "SSR_KDF_CMAC_FIN16": 0x080,
    "SSR_KDF_CMAC_CMD": 0x084,
    "SSR_KDF_CMAC_STS": 0x08C,  # status
    "SSR_KDF_CMAC_LBL0": 0x0A0,
    "SSR_KDF_CMAC_LBL1": 0x0A4,
    "SSR_KDF_CMAC_LBL2": 0x0A8,
    "SSR_KDF_CMAC_LBL3": 0x0AC,
    "SSR_KDF_CMAC_LBL4": 0x0B0,
    "SSR_KDF_CMAC_LBL5": 0x0B4,
    "SSR_KDF_CMAC_LBL6": 0x0B8,
    "SSR_KDF_CMAC_LBL7": 0x0BC,
    "SSR_KDF_CMAC_ST": 0x0CC,  # self-test
    "SSR_KDF_HKDF_IKM0": 0x100,
    "SSR_KDF_HKDF_IKM1": 0x104,
    "SSR_KDF_HKDF_IKM2": 0x108,
    "SSR_KDF_HKDF_IKM3": 0x10C,
    "SSR_KDF_HKDF_IKM4": 0x110,
    "SSR_KDF_HKDF_IKM5": 0x114,
    "SSR_KDF_HKDF_IKM6": 0x118,
    "SSR_KDF_HKDF_IKM7": 0x11C,
    "SSR_KDF_HKDF_IKM8": 0x120,
    "SSR_KDF_HKDF_IKM9": 0x124,
    "SSR_KDF_HKDF_IKM10": 0x128,
    "SSR_KDF_HKDF_IKM11": 0x12C,
    "SSR_KDF_HKDF_IKM12": 0x130,
    "SSR_KDF_HKDF_IKM13": 0x134,
    "SSR_KDF_HKDF_IKM14": 0x138,
    "SSR_KDF_HKDF_IKM15": 0x13C,
    "SSR_KDF_HKDF_SALT0": 0x140,
    "SSR_KDF_HKDF_SALT1": 0x144,
    "SSR_KDF_HKDF_SALT2": 0x148,
    "SSR_KDF_HKDF_SALT3": 0x14C,
    "SSR_KDF_HKDF_SALT4": 0x150,
    "SSR_KDF_HKDF_SALT5": 0x154,
    "SSR_KDF_HKDF_SALT6": 0x158,
    "SSR_KDF_HKDF_SALT7": 0x15C,
    "SSR_KDF_HKDF_INFO0": 0x160,
    "SSR_KDF_HKDF_INFO1": 0x164,
    "SSR_KDF_HKDF_INFO2": 0x168,
    "SSR_KDF_HKDF_INFO3": 0x16C,
    "SSR_KDF_HKDF_INFO4": 0x170,
    "SSR_KDF_HKDF_INFO5": 0x174,
    "SSR_KDF_HKDF_INFO6": 0x178,
    "SSR_KDF_HKDF_INFO7": 0x17C,
    "SSR_KDF_HKDF_INFO8": 0x180,
    "SSR_KDF_HKDF_INFO9": 0x184,
    "SSR_KDF_HKDF_INFO10": 0x188,
    "SSR_KDF_HKDF_INFO11": 0x18C,
    "SSR_KDF_HKDF_STS": 0x198,
    "SSR_KDF_HKDF_CMD": 0x19C,
    "SSR_KDF_HKDF_OUT0": 0x1C0,
    "SSR_KDF_HKDF_OUT1": 0x1C4,
    "SSR_KDF_HKDF_OUT2": 0x1C8,
    "SSR_KDF_HKDF_OUT3": 0x1CC,
    "SSR_KDF_HKDF_OUT4": 0x1D0,
    "SSR_KDF_HKDF_OUT5": 0x1D4,
    "SSR_KDF_HKDF_OUT6": 0x1D8,
    "SSR_KDF_HKDF_OUT7": 0x1DC,
    "SSR_KDF_HKDF_OUT8": 0x1E0,
    "SSR_KDF_HKDF_OUT9": 0x1E4,
    "SSR_KDF_HKDF_OUT10": 0x1E8,
    "SSR_KDF_HKDF_OUT11": 0x1EC,
    "SSR_KDF_HKDF_OUT12": 0x1F0,
    "SSR_KDF_HKDF_OUT13": 0x1F4,
    "SSR_KDF_HKDF_OUT14": 0x1F8,
    "SSR_KDF_HKDF_OUT15": 0x1FC,
}

pka_regs = {
    "SSR_PKA_CTRL":0,
    "SSR_PKA_CFG":0x010,
    "SSR_PKA_START":0x100,
    "SSR_PKA_DONE":0x200,
    "SSR_PKA_RESULT_ACK":0x204,
    "SSR_PKA_STATUS_MASK":0x208,
    "SSR_PKA_OP_TYPE":0x20C,
    "SSR_PKA_RSA_KEY_IDX":0x26C,
    "SSR_PKA_RSA_KEY_ZERO":0x270,
    "SSR_PKA_ECC_CURVE":0x2B8,
    "SSR_PKA_ECC_OP_FIFO"  :0x2CC,
    "SSR_PKA_ECC_DOM_FIFO" :0x2D0,
    "SSR_PKA_ECC_OP_B_FIFO":0x2D4,
    "SSR_PKA_ECC_OP_C_FIFO":0x2D8,
    "SSR_PKA_ECC_OP_D_FIFO":0x2DC,
    "SSR_PKA_ECC_OP_E_FIFO":0x2F8,
    "SSR_PKA_OP_A"         :0x400,
    "SSR_PKA_OP_B"         :0x800,
    "SSR_PKA_OP_C"         :0xC00
}

class SSR(metaclass=LogBase):
    def __init__(self, setup, loglevel=logging.INFO, gui: bool = False):
        self.__logger, self.info, self.debug, self.warning, self.error = logsetup(self, self.__logger, loglevel, gui)
        self.hwcode = setup.hwcode
        self.ssr_base = setup.ssr_base
        self.ssr_clk_base = setup.ssr_clk_base
        self.read32 = setup.read32
        self.write32 = setup.write32
        self.writemem = setup.writemem
        self.da_payload_addr = setup.da_payload_addr
        self.ssr = SSRCrypto(read32=self.read32, write32=self.write32, setup=setup, loglevel=loglevel, gui=gui)

    def generate_rpmb(self, level=0):
        rpmb_ikey = bytearray(b"RPMB KEY")
        rpmb_salt = bytearray(b"SASI")
        for i in range(len(rpmb_ikey)):
            rpmb_ikey[i] = rpmb_ikey[i] + level
        for i in range(len(rpmb_salt)):
            rpmb_salt[i] = rpmb_salt[i] + level
        if level == RpmbType.AES_IMG_ENC.value:
            # AES_IMG_ENC
            rpmb_ikey = bytearray(b"FIRMWARE")
            rpmb_salt = bytearray(b"ENCC")
        elif level == RpmbType.MOTOROLA.value:
            # Motorola
            rpmb_ikey = bytearray(b"CCUSTOMM")
            rpmb_salt = bytearray(b"MOTO")
        elif level == RpmbType.BASE_KEY.value:
            # Base_Key
            rpmb_ikey = bytearray(b"BASE_KEY")
            rpmb_salt = bytearray(b"9527")
        elif level == 7:
            rpmb_ikey = bytearray(b"CBTFZ\xAB\x65\x60")
            rpmb_salt = bytearray(b"8638")
        elif level == 8:
            rpmb_ikey = bytearray(b"A@RD^JDX")
            rpmb_salt = bytearray(b"8416")
        ret, derived = self.ssr.key_derive(kdf_slot_idx=KDFType.SW_KEY.value, key_len_bytes=16, key=rpmb_ikey,
                                           context=rpmb_salt)

        return derived


class SSR_PKA_ERROR(Enum):
    TIMEOUT = 0x7241
    MODE_OUT_OF_RANGE = 0x7242
    ECC_INVALID_CURVE = 0x725A


class SSR_CCC_ERROR(Enum):
    TIMEOUT = 0x7275
    ERROR = 0x724E


class SSR_ERROR(Enum):
    INVALID_PARAM = 0x7245
    INVALID_KEY_LEN = 0x7246
    NULL_POINTER = 0x7247
    INVALID_MODE = 0x724C
    INVALID_RANGE = 0x7256
    TIMEOUT = 0x7262
    SELFTEST_FAIL = 0x7268


class SSR_KDF_ERROR(Enum):
    TIMEOUT = 0x7262
    SELFTEST_FAIL = 0x7268
    NULL_PTR = 0x7247
    BAD_SIZE = 0x7246
    BAD_CONFIG = 0x724C
    HW_UNKNOWN = 0x724B


class SSRCrypto(metaclass=LogBase):
    """
    SSR Hardware Crypto class for key derivation operations.
    
    This class implements the key derivation function (KDF) found in SSR
    hardware
    """

    # KDF hardware to software error mapping
    # Maps hardware status bit index to software error code
    KDF_HW2SW_ERROR = {
        0: 0,  # No error (shouldn't happen if status_lower != 0)
        1: 0x7249,  # Status bit 0 set
        2: 0x724A,  # Status bit 1 set
        3: 0x724B,  # Status bit 2 set
        4: 0x724C,  # Status bit 3 set
        5: 0x724D,  # Status bit 4 set
        6: 0x724E,  # Status bit 5 set
        7: 0x724F,  # Status bit 6 set
        8: 0x7250,  # Status bit 7/8 set
    }

    # Derive length lookup table for different modes
    maxlength = [AESKeyLen.AES_256.value, AESKeyLen.AES_128.value,
                 AESKeyLen.AES_192.value]  # Index by derive_mode (0, 1, 2)

    def __init__(self, read32: Optional[Callable[[int], int]] = None,
                 write32: Optional[Callable[[int, int], None]] = None,
                 setup=None,
                 loglevel=logging.INFO, gui: bool = False):
        """
        Initialize SSR hardware crypto
        
        Args:
            read32: Function to read 32-bit value from address
            write32: Function to write 32-bit value to address
        """
        self.__logger, self.info, self.debug, self.warning, self.error = logsetup(self, self.__logger, loglevel, gui)
        self.ssr_clk_base = setup.ssr_clk_base
        self.ssr_base = setup.ssr_base
        if self.ssr_clk_base is not None:
            self.ssr_clk_cfg = self.ssr_clk_base
            self.ssr_clk_cfg_1 = self.ssr_clk_base + 0x4
            self.ssr_clk_cfg_1 = self.ssr_clk_base + 0x8
        if self.ssr_base is not None:
            self.ssr_lcs_base = self.ssr_base + 0x18
            self.ssr_rng_base = self.ssr_base + 0x1000
            self.ssr_kdf_base = self.ssr_base + 0x3000
            self.ssr_ccc_base = self.ssr_base + 0x5000
            self.ssr_pka_base = self.ssr_base + 0xA000
            self.ccc = RegisterMap(ccc_regs, setup.read32, setup.write32, self.ssr_ccc_base)
            self.kdf = RegisterMap(kdf_regs, setup.read32, setup.write32, self.ssr_kdf_base)
            self.clk = RegisterMap(clk_regs, setup.read32, setup.write32, self.ssr_clk_base)
            self.pka = RegisterMap(pka_regs, setup.read32, setup.write32, self.ssr_pka_base)
        self.read32 = read32
        self.write32 = write32

    def setbits(self, addr: int, mask: int) -> None:
        reg = self.read32(addr)
        self.write32(addr, reg | mask)

    def clrbits(self, addr: int, mask: int) -> None:
        reg = self.read32(addr)
        self.write32(addr, reg & (~mask & 0xFFFFFFFF))

    def set_bit_mask(self, addr: int, val: int, mask: int) -> int:
        if val > 1:
            return -1

        if val:
            self.setbits(addr, mask)
        else:
            self.clrbits(addr, mask)
        return 0

    def ssr_cc_init(self):
        self.ccc.HW_INIT_CFG0 = SSR_INIT_MAGIC1
        self.ccc.HW_INIT_CFG1 = SSR_INIT_MAGIC2

    def ssr_cc_skip_keyslot_init(self):
        val = self.ccc.SKIP_KS_INIT.value | 1
        self.ccc.SKIP_KS_INIT = val

    def ssr_rng_clk(self, enable:bool):
        return self.set_bit_mask(self.ssr_clk_base, enable, SSR_CLK_RNG)

    def ssr_ccc_clk(self, enable:bool):
        return self.set_bit_mask(self.ssr_clk_base, enable, SSR_CLK_CCC)

    def ssr_kdf_clk(self, enable:bool):
        return self.set_bit_mask(self.ssr_clk_base, enable, SSR_CLK_KDF)

    def ssr_pka_clk(self, enable:bool):
        return self.set_bit_mask(self.ssr_clk_base, enable, SSR_CLK_PKA)

    def ssr_rng_set_clk_rate(self, rate:int):
        if rate > 3:
            return SSR_ERROR.INVALID_RANGE
        self.clk.CFG_17_CLR = 0x7F
        if rate != 0:
            self.clk.CLK_17_SET = rate
        self.clk.CLK_CFG_UPDATE2 = 0x40

    def ssr_ccc_set_clk_rate(self, rate:int):
        if rate > 5:
            return SSR_ERROR.INVALID_RANGE
        self.clk.CFG_16_CLR = 0x7F0000
        if rate != 0:
            self.clk.CLK_16_SET = (rate<<16)&0xFFFFFFFF
        self.clk.CLK_CFG_UPDATE2 = 0x10

    def ssr_kdf_set_clk_rate(self, rate: int):
        if rate > 5:
            return SSR_ERROR.INVALID_RANGE
        self.clk.CFG_16_CLR = 0x7F000000
        if rate != 0:
            self.clk.CLK_16_SET = (rate << 24) & 0xFFFFFFFF
        self.clk.CLK_CFG_UPDATE2 = 0x20

    def ssr_pka_set_clk_rate(self, rate:int):
        if rate > 5:
            return SSR_ERROR.INVALID_RANGE
        self.clk.CFG_16_CLR = 0x7F00
        if rate != 0:
            self.clk.CLK_16_SET = (rate << 8) & 0xFFFFFFFF
        self.clk.CLK_CFG_UPDATE2 = 0x08

    def ssr_lcs_get(self):
        self.ssr_ccc_clk(enable=True)
        self.ssr_kdf_clk(enable=True)
        val = self.ssr_get_lcs()
        self.ssr_ccc_clk(enable=False)
        self.ssr_kdf_clk(enable=False)
        return val

    def ssr_get_lcs(self):
        return (self.read32(self.ssr_lcs_base) >> 13) & 0xF

    def bytes_to_dword(self, data):
        if len(data) % 4:
            data += b'\x00' * (4 - (len(data) % 4))
        return [int.from_bytes(data[i * 4:i * 4 + 4], 'little') for i in range(len(data) // 4)]

    def data_to_paddr(self, paddr: int = 0, data: bytes = b""):
        values = self.bytes_to_dword(data)
        for i in range(len(values)):
            self.write32(paddr + i * 4, values[i])

    def ssr_kdf_enclk(self, base: int, value: int) -> int:
        """
        Enable/disable KDF clock
        
        Args:
            base: Base register address
            value: 0 to disable, 1 to enable
            
        Returns:
            0 on success, error code on failure
        """
        if value > 1:
            return SSR_ERROR.INVALID_PARAM.value

        reg_val = self.read32(base)
        # Clear bit 16, then set if value is non-zero
        reg_val = (reg_val & 0xFFFEFFFF) | ((1 if value != 0 else 0) << 16)
        self.write32(base, reg_val)
        return 0

    def ssr_polling_when(self, reg_addr: int, mask: int, value: int, timeout: int) -> int:
        """
        Poll register while condition is met or timeout
        
        Args:
            reg_addr: Register address to poll
            mask: Bit mask to check
            value: value after applying mask
            timeout: timeout in milliseconds
            
        Returns:
            0 on success, non-zero on timeout
        """
        start = time.time()
        timeout_sec = timeout / 1000.0

        while time.time() - start < timeout_sec:
            val = self.read32(reg_addr)
            if (val & mask) != value:
                return 0
            time.sleep(0.001)

        return 1  # Timeout

    def ssr_polling_until(self, reg_addr: int, mask: int, value: int, timeout: int) -> int:
        """
        Poll register until condition is met or timeout

        Args:
            reg_addr: Register address to poll
            mask: Bit mask to check
            value: value after applying mask
            timeout: timeout in milliseconds

        Returns:
            0 on success, non-zero on timeout
        """
        import time
        start = time.time()
        timeout_sec = timeout / 1000.0

        while time.time() - start < timeout_sec:
            val = self.read32(reg_addr)
            if (val & mask) == value:
                return 0
            time.sleep(0.001)

        return 1  # Timeout

    def kdf_write_window(self, dst: int, data, words, rtl: bool):
        staging = bytearray(17 * 4)
        if rtl:
            wc = words
            staging[(wc * 4) - len(data):(wc * 4)] = data
        else:
            wc = len(data) + 3 // 4
            staging[:len(data)] = data
        for i in range(wc):
            self.write32(dst + i * 4, self._bswap32(staging[wc - 1 - i]))

    def field_prep(self, mask: int, val: int) -> int:
        """
        - Shifts `val` to the position of the lowest set bit in `mask`
        - Masks the result so it only occupies the bits defined by `mask`
        - Works with any mask size (Python integers are arbitrary precision)
        - Identical behaviour to __builtin_ctzll for 64-bit masks
        """
        if mask == 0:
            return 0  # avoid division-by-zero / undefined behaviour

        # Compute ctz (count trailing zeros) using the classic mask & -mask trick
        # This is the Python equivalent of __builtin_ctzll(mask)
        lowest_set_bit = mask & -mask
        shift = lowest_set_bit.bit_length() - 1

        # Apply the same operations as the C macro
        return (val << shift) & mask

    def field_get(self, mask: int, reg: int) -> int:
        """
        Python equivalent of the Linux kernel macro:

        #define FIELD_GET(mask, reg) \
            (((reg) & (mask)) >> (__builtin_ctzll(mask)))

        Extracts the value of a bitfield from a register.

        - Isolates the bits defined by `mask`
        - Shifts them right so the field value starts at bit 0
        - Identical behaviour to __builtin_ctzll for any mask size

        Works with FIELD_PREP from the previous conversion:
            reg = FIELD_PREP(GENMASK(15, 8), 0xAB)
            value = FIELD_GET(GENMASK(15, 8), reg)   # → 0xAB
        """
        if mask == 0:
            return 0  # avoid undefined behaviour

        # Same ctz trick used in FIELD_PREP (Python equivalent of __builtin_ctzll)
        lowest_set_bit = mask & -mask
        shift = lowest_set_bit.bit_length() - 1

        # Literal translation of the C macro
        return (reg & mask) >> shift

    def ssr_kdf_hkdf_sha256(self, ikm, info, salt=None, derive_len: int = 0x20):
        if salt is not None:
            self.kdf_write_window(self.kdf.SSR_KDF_HKDF_SALT7.addr, salt, 0, False)
        self.kdf_write_window(self.kdf.SSR_KDF_HKDF_IKM15, ikm, 0, False)
        self.kdf_write_window(self.kdf.SSR_KDF_HKDF_INFO11, info, 0, False)
        cmd = (SSR_KDF_HKDF_CMD_START |
               SSR_KDF_HKDF_CMD_FIXED |
               SSR_KDF_HKDF_CMD_NO_SALT if salt is None else 0 |
                                                             self.field_prep(SSR_KDF_HKDF_CMD_IKM_LEN, len(ikm)) |
                                                             self.field_prep(SSR_KDF_HKDF_CMD_SALT_LEN,
                                                                             0 if salt is None else len(salt)) |
                                                             self.field_prep(SSR_KDF_HKDF_CMD_INFO_LEN, len(info)))

        self.kdf.SSR_KDF_HKDF_CMD = cmd
        if self.ssr_polling_when(self.kdf.SSR_KDF_HKDF_CMD.addr, 0, 0, 5000):
            return SSR_KDF_ERROR.TIMEOUT
        status = self.kdf.SSR_KDF_HKDF_STS
        if self.field_get(SSR_KDF_HKDF_STS_ERR, status):
            return SSR_KDF_ERROR.HW_UNKNOWN
        out = []
        for n in range(derive_len // 4):
            out = self._bswap32(self.kdf.SSR_KDF_HKDF_OUT0.addr + 4)
        return b"".join(out)

    def ssr_kdf_kbkdf_cmac_counter(
            self,
            hw_ctx_base: int,
            key_type: int,
            label: Optional[bytes],
            derive_mode: int,
            key_material: bytes,
            key_material_len: int,
            derived_key_len: int
    ) -> Tuple[int, bytes]:
        """
        Perform KBKDF CMAC Counter mode key derivation
        
        This implements the hardware KDF operation using CMAC counter mode,
        matching the C implementation's register operations and byte ordering.
        
        Args:
            hw_ctx_base: Hardware context base address
            key_type: Key type (0-15)
            label: Label bytes (required if key_type is 0)
            derive_mode: Derivation mode (0-2)
            key_material: Input key material
            key_material_len: Length of key material
            derived_key_len: Desired derived key length in bytes
            
        Returns:
            Tuple of (error_code, derived_key_bytes)
        """
        if derive_mode > 2:
            return SSR_ERROR.INVALID_MODE.value, b''

        if derived_key_len == 0 or derived_key_len > 0x40:
            return SSR_ERROR.INVALID_KEY_LEN.value, b''

        context_len = self.maxlength[derive_mode]
        length_mode = derive_mode

        # Calculate block count (derived_key_len / 16, rounded up)
        if (derived_key_len & 0xF) != 0:
            block_count = (derived_key_len >> 4) + 1
        else:
            block_count = derived_key_len >> 4

        # Validate key material
        if not key_material:
            return SSR_ERROR.NULL_POINTER.value, b''

        if key_material_len >= 0x44:
            return SSR_ERROR.INVALID_KEY_LEN.value, b''

        # Initialize IO buffer (68 bytes)
        io_buffer = bytearray(0x44)

        # Copy key material to end of io_buffer (right-aligned at offset 68 - key_material_len)
        end_offset = 0x44 - key_material_len
        io_buffer[end_offset:0x44] = key_material[:key_material_len]

        # Pack as QWORDs for byte swapping operations
        padded = io_buffer + bytes(4)  # Pad to 72 bytes for 9 QWORDs
        qwords = struct.unpack('<9Q', padded)

        # Write to hardware context registers with byte swapping
        io_buffer_0 = int.from_bytes(io_buffer[:4], 'little') if len(io_buffer) >= 4 else 0
        self.kdf.SSR_KDF_CMAC_FIN16 = self._bswap32(io_buffer_0 | key_material_len)

        # Write remaining key material registers (hw_ctx[16..31])
        reg_idx = 0x0
        for i in range(8, 0, -1):  # 8 down to 1
            qword = qwords[i]
            low = qword & 0xFFFFFFFF
            high = (qword >> 32) & 0xFFFFFFFF
            self.write32(self.kdf.SSR_KDF_CMAC_FIN0.addr + reg_idx * 4, self._bswap32(high))
            reg_idx += 1
            self.write32(self.kdf.SSR_KDF_CMAC_FIN0.addr + reg_idx * 4, self._bswap32(low))
            reg_idx += 1

        # Handle label if key_type is 0
        if key_type == KDFType.SW_KEY.value:
            if label is None:
                return SSR_ERROR.NULL_POINTER.value, b''

            # Initialize label buffer (32 bytes)
            label_buffer = bytearray(32)

            # Copy label to end of label_buffer (right-aligned by context_len)
            # memcpy((char *)&io_buffer[4] - context_len, label, context_len)
            label_copy_len = min(len(label), context_len)
            label_start = 32 - context_len
            label_buffer[label_start:label_start + label_copy_len] = label[:label_copy_len]

            # Pack as QWORDs
            label_qwords = struct.unpack('<4Q', label_buffer)

            # Write label to hw_ctx[40..47] with byte swapping
            reg_idx = 0x0
            for qword in label_qwords:
                low = qword & 0xFFFFFFFF
                high = (qword >> 32) & 0xFFFFFFFF
                self.write32(self.kdf.SSR_KDF_CMAC_LBL0.addr + reg_idx * 4, self._bswap32(high))
                reg_idx += 1
                self.write32(self.kdf.SSR_KDF_CMAC_LBL0.addr + reg_idx * 4, self._bswap32(low))
                reg_idx += 1

        control_val = ((length_mode & 3) << 6) | ((key_type & 0xF) << 8) | (block_count << 16) | 1
        self.kdf.SSR_KDF_CMAC_CMD = control_val

        # Poll for completion (wait for bit 0 to be set)
        if self.ssr_polling_when(self.kdf.SSR_KDF_CMAC_CMD.addr, 1, 1, 0x1388):
            self.error("Timeout when trying to run ssr crypto engine")
            return 0x7262, b''

        # Read and check status register
        status_reg = self.kdf.SSR_KDF_CMAC_STS.value
        status_lower = status_reg & 0x7FF

        if status_lower != 0:
            # Determine error code from status bits
            if status_reg & 1:
                errorcode = 0
            elif status_reg & 2:
                errorcode = 1
            elif status_reg & 4:
                errorcode = 2
            elif status_reg & 8:
                errorcode = 3
            elif status_reg & 0x10:
                errorcode = 4
            elif status_reg & 0x20:
                errorcode = 5
            elif status_reg & 0x40:
                errorcode = 6
            elif status_reg & 0x80:
                errorcode = 7
            elif status_reg & 0x100:
                errorcode = 8
            else:
                return 0x724B, b''

            return self.KDF_HW2SW_ERROR.get(errorcode, 0x724B), b''

        derived_key = bytearray(64)
        dst_idx = 0

        for base in [self.kdf.SSR_KDF_CMAC_OUT3.addr, self.kdf.SSR_KDF_CMAC_OUT7.addr, self.kdf.SSR_KDF_CMAC_OUT11.addr,
                     self.kdf.SSR_KDF_CMAC_OUT15.addr]:
            regs = []
            for offset in range(-3, 1):
                regs.append(self.read32(base + (offset * 4)))

            for i in range(3, -1, -1):
                val = regs[i]
                # 32-bit byte swap: B0 B1 B2 B3 -> B3 B2 B1 B0
                swapped = ((val & 0xFF) << 24) | ((val & 0xFF00) << 8) | \
                          ((val & 0xFF0000) >> 8) | ((val >> 24) & 0xFF)

                if dst_idx + 4 <= len(derived_key):
                    derived_key[dst_idx:dst_idx + 4] = swapped.to_bytes(4, 'little')
                    dst_idx += 4

        return 0, bytes(derived_key[:derived_key_len])

    def _bswap32(self, value: int) -> int:
        """
        Byte swap 32-bit integer (little-endian <-> big-endian)
        B0 B1 B2 B3 -> B3 B2 B1 B0
        """
        value = value & 0xFFFFFFFF
        return ((value & 0xFF) << 24) | ((value & 0xFF00) << 8) | \
            ((value & 0xFF0000) >> 8) | ((value >> 24) & 0xFF)

    def key_derive(self, kdf_slot_idx: int, key_len_bytes: int, key: bytes, context: bytes, label: bytes = None) -> \
    Tuple[int, bytes]:
        """
        Derive a key using KDF
        
        This is the main entry point matching the C function key_derive().
        It combines two input key materials (IKM1 and IKM2) from the RPMB
        key structure and derives a key using the hardware KDF.
        
        Args:
            kdf_slot_idx: KDF slot index (0 or 1)
            key_len_bytes: Desired key length in bytes (max 64)

        Returns:
            Tuple of (return_code, derived_key_bytes)
            - return_code: 0 on success, negative or error code on failure
            - derived_key_bytes: The derived key (zeroed on failure)
        """
        ret = 0

        # Validate parameters
        if kdf_slot_idx > 1 or key_len_bytes == 0:
            ret = -1
            self.debug("key_derive fails(0x%x)", ret)
            return ret, b'\x00' * key_len_bytes

        # Initialize KDF input buffer (64 bytes = 8 QWORDs)
        kdf_input_buf = bytearray(64)

        ikm1_ptr = key
        ikm1_len = len(key)
        context_ptr = context
        context_len = len(context)

        # Validate inputs: both keys must exist and total length < 0x41 (65)
        if not ikm1_ptr or not context_ptr or (context_len + ikm1_len) >= 0x41:
            ret = -1
            self.debug("key_derive fails(0x%x)", ret)
            return ret, b'\x00' * key_len_bytes

        kdf_input_len = 0xFFFFFFFF

        # Build KDF input if length constraints are satisfied
        if ikm1_len <= 0x40 and context_len <= 0x40:
            buf_pos = 0

            # Copy ikm1 to start of buffer
            if ikm1_len > 0:
                kdf_input_buf[0:ikm1_len] = ikm1_ptr[:ikm1_len]
                buf_pos = ikm1_len

            # Add separator byte (0)
            kdf_input_buf[buf_pos] = 0
            buf_pos += 1

            # Copy ikm2 after separator
            if context_len > 0:
                kdf_input_buf[buf_pos:buf_pos + context_len] = context_ptr[:context_len]
                buf_pos += context_len

            # Add key length in bits at the end
            kdf_input_buf[buf_pos] = 8 * key_len_bytes

            # Calculate total input length (C: _kdf_input_buf_plus_one - kdf_input_buf + 1)
            kdf_input_len = buf_pos + 1

        # Enable KDF clock
        clk_ret = self.ssr_kdf_enclk(self.ssr_clk_cfg, 1)
        if clk_ret != 0:
            ret = clk_ret
            self.debug("key_derive fails(0x%x)", ret)
            return ret, b'\x00' * key_len_bytes

        # Perform KDF operation
        ret, derived_key = self.ssr_kdf_kbkdf_cmac_counter(
            self.ssr_kdf_base,
            4,  # key_type = 4 (from C code)
            label,  # label (not used when key_type != 0)
            0,  # derive_mode
            bytes(kdf_input_buf[:kdf_input_len]) if kdf_input_len != 0xFFFFFFFF else b'',
            kdf_input_len if kdf_input_len != 0xFFFFFFFF else 0,
            key_len_bytes
        )

        # Disable KDF clock
        self.ssr_kdf_enclk(self.ssr_clk_cfg, 0)

        if ret != 0:
            self.debug("key_derive fails(0x%x)", ret)
            return ret, b'\x00' * key_len_bytes

        return ret, derived_key

class SSR_PKA(SSRCrypto):
    def __init__(self, setup, loglevel=logging.INFO, gui=False):
        super(SSR_PKA, self).__init__(setup, loglevel=loglevel, gui=gui)
        self.data_len = 0
        self.buf = bytearray(64)
        self.paddr = 0x69000000

    def pka_write(self, base:int, data:list, nwords:int):
        for i in range(nwords-1,0,-1):
            self.write32(base+(i*4),self._bswap32(data[i]))

    def pka_read(self, base, nwords:int):
        dst = []
        for i in range(nwords-1,0,-1):
            dst.append(self._bswap32(self.read32(base+(i*4))))
        return dst

    def pka_rsa_modexp(self, mode:int, base:int, exponent:int, modulus:int, timeout:int):
        if mode >= 4:
            return SSR_PKA_ERROR.MODE_OUT_OF_RANGE
        key_words = (mode+1)*32
        self.pka.SSR_PKA_OP_TYPE = PKA_OP.RSA_MODEXP.value
        self.pka.SSR_PKA_RSA_KEY_IDX = mode
        self.pka.SSR_PKA_RSA_KEY_ZERO = 0
        self.pka_write(self.pka.SSR_PKA_OP_A.addr, self.bytes_to_dword(long_to_bytes(exponent)), key_words)
        self.pka_write(self.pka.SSR_PKA_OP_B.addr, self.bytes_to_dword(long_to_bytes(modulus)), key_words)
        self.pka_write(self.pka.SSR_PKA_OP_C.addr, self.bytes_to_dword(long_to_bytes(base)), key_words)
        self.pka.SSR_PKA_START = 0
        if self.ssr_polling_until(self.pka.SSR_PKA_DONE.addr, 1, 1, timeout):
            return SSR_PKA_ERROR.TIMEOUT
        self.pka.SSR_PKA_RESULT_ACK = 1
        result = b"".join(self.pka_read(self.pka.SSR_PKA_OP_C.addr, key_words))
        ctrl = self.pka.SSR_PKA_CTRL.value
        self.pka.SSR_PKA_CTRL = ctrl & ((~2)&0xFFFFFFFF)
        self.pka.SSR_PKA_CTRL = ctrl & ((~2)&0xFFFFFFFF) | 2
        return result

    def pka_ecc_push_operant(self, fifo:int, src:list, nwords:int):
        for i in range(nwords-1,0,-1):
            self.write32(fifo, self._bswap32(src[i]))
        for i in range(13):
            self.write32(fifo,0)

    def pka_ecc_push_domain(self, table:list, word_count:int):
        for i in range(word_count-1,0,-1):
            self.write32(self.pka.SSR_PKA_ECC_DOM_FIFO, self._bswap32(table[i]))
        for i in range(19):
            self.write32(self.pka.SSR_PKA_ECC_DOM_FIFO, 0)

    def pka_ecc_pop_operand(self, fifo:int, nwords:int):
        dst = []
        for i in range(nwords-1,0,-1):
            dst.append(self._bswap32(self.read32(fifo)))
        return dst

    def pka_ecc_op(self, curve:int, op_code:int, operands:list):
        if curve == PKA_ECC.ECC_CURVE_NIST_P256:
            dom = ecc_domain_p256
            wc = SSR_PKA_ECC_P256_WORDS
        elif curve == PKA_ECC.ECC_CURVE_NIST_P384:
            dom = ecc_domain_p384
            wc = SSR_PKA_ECC_P384_WORDS
        else:
            raise NotImplementedError
        self.pka.SSR_PKA_OP_TYPE = op_code
        self.pka.SSR_PKA_ECC_CURVE = curve
        for operand in operands:
            self.pka_ecc_push_operant(self.pka.SSR_PKA_ECC_DOM_FIFO.addr,operand, wc)
        self.pka_ecc_push_domain(dom, wc)
        self.pka.SSR_PKA_START = 0
        if self.ssr_polling_until(self.pka.SSR_PKA_DONE.addr, 1, 1, SSR_TIMEOUT):
            return SSR_PKA_ERROR.TIMEOUT
        self.pka.SSR_PKA_RESULT_ACK = 1
        out_x = self.pka_ecc_pop_operand(self.pka.SSR_PKA_ECC_OP_FIFO.addr, wc)
        out_y = self.pka_ecc_pop_operand(self.pka.SSR_PKA_ECC_DOM_FIFO.addr, wc)
        ctrl = self.pka.SSR_PKA_CTRL.value
        self.SSR_PKA_CTRL = ctrl & ((~2)&0xFFFFFFFF)
        self.SSR_PKA_CTRL = ctrl & ((~2)&0xFFFFFFFF) | 2
        return out_x, out_y

class SSR_SHA(SSRCrypto):
    def __init__(self, setup, loglevel=logging.INFO, gui=False):
        super(SSR_SHA, self).__init__(setup, loglevel=loglevel, gui=gui)
        self.data_len = 0
        self.buf = bytearray(64)
        self.paddr = 0x69000000

    def ssr_ccc_sha256_compress(self, length: int):
        first = self.ccc.BASE.value == 0
        bit_len = length * 8
        high_paddr = (self.paddr >> 32) != 0
        high_bitlen = (bit_len >> 32) != 0
        while self.ccc.QUEUE_AVAILABLE.value & 0xFF < 6:
            pass
        cmd0 = 0x30000000 if first else 0x31000000 | high_bitlen << 7 | high_paddr << 8
        seq = (self.ccc.SHA_JOB_ID.value + 1) & 0xFFFF
        if seq == 0:
            seq = 1
        self.ccc.QUEUE = cmd0
        self.ccc.QUEUE = seq | 0 if first else 0x20000000
        self.ccc.QUEUE = (self.paddr >> 16) & 0xF0000 if high_paddr else 0
        self.ccc.QUEUE = bit_len
        self.ccc.QUEUE = self.paddr & 0xFFFFFF
        nwords = 5
        if high_bitlen:
            self.ccc.QUEUE = (bit_len >> 32)
            nwords = 6
        self.ccc.QUEUE_AVAILABLE = nwords
        if self.ssr_polling_when(self.ccc.SHA_JOB_ID.addr, 0xFFFF, seq, SSR_TIMEOUT):
            return SSR_CCC_ERROR.TIMEOUT.value
        if self.ccc.SHA_JOB_ID.value < 0:
            return SSR_CCC_ERROR.ERROR.value
        return 0

    def ssr_ccc_sha384_compress(self, length: int):
        first = self.ccc.BASE.value == 0
        bit_len = length * 8
        high_paddr = (self.paddr >> 32) != 0
        high_bitlen = (bit_len >> 32) != 0
        while self.ccc.QUEUE_AVAILABLE.value & 0xFF < 6:
            pass
        cmd0 = (0x30000000 if first else 0x31000000 |
                                         0x2000880 if high_bitlen else 0x2000800 |
                                                                       (high_paddr & 0xFFFFFFFF) << 8)
        seq = (self.ccc.SHA_JOB_ID.value + 1) & 0xFFFF
        if seq == 0:
            seq = 1
        self.ccc.QUEUE = cmd0
        self.ccc.QUEUE = seq | 0 if first else 0x20000000
        self.ccc.QUEUE = (self.paddr >> 16) & 0xF0000 if high_paddr else 0
        self.ccc.QUEUE = bit_len
        self.ccc.QUEUE = self.paddr & 0xFFFFFF
        nwords = 5
        if high_bitlen:
            self.ccc.QUEUE = (bit_len >> 32)
            nwords = 6
        self.ccc.QUEUE_AVAILABLE = nwords
        if self.ssr_polling_when(self.ccc.SHA_JOB_ID.addr, 0xFFFF, seq, SSR_TIMEOUT):
            return SSR_CCC_ERROR.TIMEOUT.value
        if self.ccc.SHA_JOB_ID.value < 0:
            return SSR_CCC_ERROR.ERROR.value
        return 0

    def ssr_ccc_sha_read_output(self, count):
        dst = []
        for i in range(count):
            dst.append(self.read32(self.ccc.SHA_OUT.addr + ((count - 1 - i) * 4)))
        return b"".join(dst)

    def ssr_ccc_sha256_init(self):
        self.buf = bytearray(64)

    def ssr_ccc_sha256_update(self, data: bytes):
        inlen = len(data)
        pos = inlen & 0x3F
        if pos != 0:
            fill = 64 - pos
            if inlen < fill:
                self.buf[pos:pos + inlen] = data[:inlen]
                return 0
            self.buf[pos:pos + fill] = data[:fill]
            status = self.ssr_ccc_sha256_compress(64)
            if status > 0:
                return status
            data = data[fill:]
            inlen -= fill
        if inlen >= 64:
            full = inlen & ((~0x3F) & 0xFFFFFFFF)
            status = self.ssr_ccc_sha256_compress(64)
            if status > 0:
                return status
            data = data[full:]
            inlen -= full
        if inlen:
            self.buf[:inlen] = data[:inlen]
        return 0

    def ssr_ccc_sha256_done(self):
        pos = self.data_len & 0x3F
        pad_len = 64 if pos < 56 else 128
        len_off = pad_len - 8
        total = self.data_len
        pad = bytearray(128)
        pad[:len(self.buf)] = self.buf
        pad[pos] = 0x80
        bits = total * 8
        for i in range(7, 0, -1):
            pad[len_off + i] = bits & 0xFF
            bits >>= 8
        self.data_to_paddr(self.paddr, pad)
        status = self.ssr_ccc_sha256_compress(pad_len)
        if status > 0:
            return status
        dst = self.ssr_ccc_sha_read_output(8)
        return dst

    def ssr_ccc_sha256(self, data: bytes):
        inlen = len(data)
        bit_len = inlen * 8
        high_paddr = (self.paddr >> 32) != 0
        high_bitlen = (bit_len >> 32) != 0
        shatype = CCC_SHAType.SHA256.value

        while self.ccc.QUEUE_AVAILABLE.value & 0xF8 == 0:
            pass

        cmd0 = (0x30000000 |
                ((shatype & 3) << 25) & 0xFFFFFFFF |
                ((shatype >> 2 & 1) << 11) |
                high_bitlen << 7 |
                high_paddr << 8)

        seq = (self.ccc.SHA_JOB_ID.value + 1) & 0xFFFF
        if seq == 0:
            seq = 1
        self.ccc.QUEUE = cmd0
        self.ccc.QUEUE = seq | 0x80000000
        self.ccc.QUEUE = (self.paddr >> 16) & 0xF0000 if high_paddr else 0
        self.ccc.QUEUE = bit_len
        self.ccc.QUEUE = self.paddr & 0xFFFFFF
        nwords = 5
        if high_bitlen:
            self.ccc.QUEUE = (bit_len >> 32)
            nwords = 6
        self.ccc.QUEUE_AVAILABLE = nwords
        if self.ssr_polling_until(self.ccc.SHA_JOB_ID.addr, 0xFFFF, seq, SSR_TIMEOUT):
            return SSR_CCC_ERROR.TIMEOUT.value
        if self.ccc.SHA_JOB_ID.value < 0:
            return SSR_CCC_ERROR.ERROR.value
        retval = self.ssr_ccc_sha_read_output(8)
        return retval

    def ssr_ccc_sha384_init(self):
        self.buf = bytearray(128)

    def ssr_ccc_sha384_update(self, data: bytes):
        inlen = len(data)
        pos = inlen & 0x7F
        if pos != 0:
            fill = 128 - pos
            if inlen < fill:
                self.buf[pos:pos + inlen] = data[:inlen]
                return 0
            self.buf[pos:pos + fill] = data[:fill]
            status = self.ssr_ccc_sha384_compress(128)
            if status > 0:
                return status
            data = data[fill:]
            inlen -= fill
        if inlen >= 64:
            full = inlen & ((~0x7F) & 0xFFFFFFFF)
            status = self.ssr_ccc_sha384_compress(128)
            if status > 0:
                return status
            data = data[full:]
            inlen -= full
        if inlen:
            self.buf[:inlen] = data[:inlen]
        return 0

    def ssr_ccc_sha384_done(self):
        pos = self.data_len & 0x7F
        pad_len = 128 if pos < 112 else 256
        len_off = pad_len - 8
        total = self.data_len
        pad = bytearray(256)
        pad[:len(self.buf)] = self.buf
        pad[pos] = 0x80
        bits = total * 8
        for i in range(7, 0, -1):
            pad[len_off + i] = bits & 0xFF
            bits >>= 8
        self.data_to_paddr(self.paddr, pad)
        status = self.ssr_ccc_sha384_compress(pad_len)
        if status > 0:
            return status
        dst = self.ssr_ccc_sha_read_output(8)
        return dst

    def ssr_ccc_sha384(self, data: bytes):
        inlen = len(data)
        bit_len = inlen * 8
        high_paddr = (self.paddr >> 32) != 0
        high_bitlen = (bit_len >> 32) != 0
        shatype = CCC_SHAType.SHA384.value

        while (self.ccc.QUEUE_AVAILABLE.value & 0xF8) == 0:
            pass

        cmd0 = (0x30000000 |
                ((shatype & 3) << 25) & 0xFFFFFFFF |
                ((shatype >> 2 & 1) << 11) |
                high_bitlen << 7 |
                high_paddr << 8)

        seq = (self.ccc.SHA_JOB_ID.value + 1) & 0xFFFF
        if seq == 0:
            seq = 1
        self.ccc.QUEUE = cmd0
        self.ccc.QUEUE = seq | 0x80000000
        self.ccc.QUEUE = (self.paddr >> 16) & 0xF0000 if high_paddr else 0
        self.ccc.QUEUE = bit_len
        self.ccc.QUEUE = self.paddr & 0xFFFFFF
        nwords = 5
        if high_bitlen:
            self.ccc.QUEUE = (bit_len >> 32)
            nwords = 6
        self.ccc.QUEUE_AVAILABLE = nwords
        if self.ssr_polling_until(self.ccc.SHA_JOB_ID.addr, 0xFFFF, seq, SSR_TIMEOUT):
            return SSR_CCC_ERROR.TIMEOUT.value
        if self.ccc.SHA_JOB_ID.value < 0:
            return SSR_CCC_ERROR.ERROR.value
        retval = self.ssr_ccc_sha_read_output(8)
        return retval


# Example/test code
if __name__ == "__main__":
    # Example usage without hardware (for testing structure)

    # Mock read/write functions for testing
    registers = {}
    KDF_CTX_BASE = 0x14003000


    def mock_read32(addr):
        return registers.get(addr, 0)


    def mock_write32(addr, value):
        registers[addr] = value
        # Simulate status register being set after control write
        if addr == KDF_CTX_BASE + 0x84:
            # Set status to indicate success
            registers[KDF_CTX_BASE + 0x8C] = 0


    # Create instance
    ssr = SSRCrypto(mock_read32, mock_write32, setup)

    # Register key materials for slot 0
    rpmb_key = b'RPMB_KEY'
    sasi_key = b'SASI'

    # Derive a 16-byte key
    ret, derived = ssr.key_derive(kdf_slot_idx=KDFType.SW_KEY.value, key_len_bytes=16, key=rpmb_key, context=sasi_key,
                                  label=b"")
    print(f"Return code: {ret}")
    print(f"Derived key length: {len(derived)}")
    print(f"Derived key (hex): {derived.hex()}")

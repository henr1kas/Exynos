import ctypes

class SignerVer(ctypes.LittleEndianStructure):
    _pack_ = 1
    _fields_ = [
        ("signer_version", ctypes.c_char * 16),
        ("qb",             ctypes.c_char * 16), # last char either R or P, idk meaning
        ("binary_version", ctypes.c_char * 16),
        ("padding",        ctypes.c_char * 16),
        ("timestamp",      ctypes.c_char * 16),
        ("device_model",   ctypes.c_char * 32),
        ("system_rev",     ctypes.c_char * 16),
        ("kernel_rev",     ctypes.c_char * 16),
        ("build_type",     ctypes.c_char * 4),  # usr or eng
        ("frp_lock",       ctypes.c_char * 4),  # NONE or frp
        ("build_channel",  ctypes.c_char * 4),  # mrk or fac
        ("filename",       ctypes.c_char * 100),
    ]

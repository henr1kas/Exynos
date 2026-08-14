import ctypes

class SignerInfo(ctypes.LittleEndianStructure):
    _pack_ = 1
    _fields_ = [
        ("SignSystemRevision", ctypes.c_char * 16),
        ("QuickBuildId",       ctypes.c_char * 16), # R at end = Release, P=idk
        ("VersionName",        ctypes.c_char * 32),
        ("BuildTime",          ctypes.c_char * 16),
        ("ModelName",          ctypes.c_char * 32),
        ("SystemRPValue",      ctypes.c_char * 16),
        ("KernelRPValue",      ctypes.c_char * 16),
        ("BuildVarient",       ctypes.c_char * 4),  # usr or eng
        ("KillSwitchMagic",    ctypes.c_char * 4),  # frp, ral or NONE
        ("FactoryBuild",       ctypes.c_char * 4),  # fac or mrk
        ("BinaryName",         ctypes.c_char * 16),
        ("CSCQuickBuildId",    ctypes.c_char * 16), # idk1
        ("BLQuickBuildId",     ctypes.c_char * 16), # idk2
        ("Reserve",            ctypes.c_char * 52),
    ]

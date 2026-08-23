from soc import SoC, Image

def soc_data():
    return SoC(
        signing_type=0,
        odin=(
            Image("cm.bin"),
            Image("keystorage.bin"),
            Image("sboot.bin", split=(
                Image("fwbl1.bin", stage="st1"),
                Image("bl31.bin", update_header=True),
                Image("bl2.bin"),
                Image("pad.bin", stage=None),
                Image("u-boot.bin"),
                Image("el3_mon.bin"),
                Image("secure_payload.bin"),
                Image("tail.bin", stage=None),
            )),
        )
    )

from soc import SoC, Image

def soc_data():
    return SoC(
        signing_type=0,
        odin=(
            Image("cm.bin"),
            Image("sboot.bin", split=(
                Image("fwbl1.bin", stage="st1"),
                Image("bl31.bin", update_header=True),
                Image("bl2.bin"),
                Image("pad.bin", stage=None),
                Image("u-boot.bin"),
                Image("el3_mon.bin"),
                Image("tail.bin", stage=None),
            )),
            Image("modem.bin", split=(
                Image("TOC.bin", stage=None),
                Image("BOOT.bin"),
                Image("pad.bin", stage=None),
                Image("MAIN.bin"),
                Image("tail.bin", stage=None),
            )),
            Image("HERO2LTE_EUR_OPEN_HIDDEN45M.pit")
        )
    )

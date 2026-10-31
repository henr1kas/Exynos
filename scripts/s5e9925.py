from soc import SoC, Image

def soc_data():
    return SoC(
        signing_type=4,
        odin=(
            Image("fld.bin", ree=True, split=(
                Image("stsocbl1.bin", stage="st1"),
                Image("dbgc.bin"),
                Image("hostbl1.bin"),
                Image("tail.bin", stage=None), #32tag+signerv3+avb
            )),
            Image("harx.bin", ree=True, split=(
                Image("harx.bin", ree=True),
                Image("tail.bin", stage=None), # signerv3+avb
            )),
            Image("keystorage.bin", ree=True, split=(
                Image("keystorage.bin"),
                Image("tail.bin", stage=None), # signerv3+avb
            )),
            Image("ldfw.img", ree=True, split=(
                Image("ldfw.bin"),
                Image("tail.bin", stage=None), # signerv3+avb
            )),
            Image("sboot.bin", ree=True, split=(
                Image("epbl.bin", update_header=True),
                Image("bl2.bin", ree=True),
                Image("pad.bin", stage=None),
                Image("dpm.img"),
                Image("pad2.bin", stage=None),
                Image("bootload.bin", ree=True),
                Image("el3_mon.bin"),
                Image("smap_and_tail.bin", stage=None),#smap+32tag+signerv3+avb
            )),
            Image("ssp.img", stage=None), #idk
            Image("tzar.img", ree=True),
            Image("tzsw.img", ree=True, split=(
                Image("tzsw.bin"),
                Image("tail.bin", stage=None), # signerv3+avb
            )),
            Image("uh.bin", ree=True),
            Image("up_param.bin", stage=None),
            Image("B0S_EUR_OPENX.pit", ree=True), # TODO: device specific (take any .pit?)
        )
    )

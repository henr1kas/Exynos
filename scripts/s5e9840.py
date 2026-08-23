from soc import SoC, Image

def soc_data():
    return SoC(
        signing_type=4,
        odin=(
            Image("dpm.img"),
            Image("harx.bin", ree=True, split=(
                Image("harx.bin", ree=True),
                Image("tail.bin", stage=None), # signerv3, avb footer
            )),
            Image("keystorage.bin", ree=True, split=(
                Image("keystorage.bin"),
                Image("tail.bin", stage=None), # signerv3, avb footer
            )),
            Image("ldfw.img", ree=True, split=(
                Image("ldfw.bin"),
                Image("tail.bin", stage=None), # signerv3, avb footer
            )),
            #Image("O1S_EUR_OPENX.pit", ree=True), # TODO: device specific (take any .pit?)
            Image("sboot.bin", ree=True, split=(
                Image("bl1.bin", stage="st1"),
                Image("epbl.bin", update_header=True),
                Image("bl2.bin", ree=True),
                Image("pad.bin", stage=None),
                Image("dpm.img"),
                Image("bootload.bin", ree=True),
                Image("el3_mon.bin"),
                Image("tail.bin", stage=None),# 32 evt info, signerv3, avb footer
            )),
            Image("ssp.img", stage=None), # not sure :D
            Image("tzar.img", ree=True),
            Image("tzsw.img", ree=True, split=(
                Image("tzsw.bin"),
                Image("tail.bin", stage=None), # signerv3, avb footer
            )),
            Image("uh.bin", ree=True),
            Image("up_param.bin", stage=None),
            Image("vddcal_fw.bin", ree=True),
        )
    )
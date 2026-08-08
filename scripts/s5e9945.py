from soc import SoC, Image

def soc_data():
    return SoC(
        signing_type=4,
        odin=(
            Image("dtp.bin", ree=True, split=(
                Image("dtp.bin", ree=True),
                Image("tail.bin", stage=None), # signerv3
            )),
            Image("E2S_EUR_OPENX.pit", ree=True),
            Image("fld.bin", ree=True, split=(
                Image("pspbl1.bin", stage="st1"),
                Image("dbgc.bin"),
                Image("hostbl1.bin"),
                Image("tail.bin", stage=None), #32tag+signerv3
            )),
            Image("harx.bin", ree=True, split=(
                Image("harx.bin", ree=True),
                Image("tail.bin", stage=None), # signerv3
            )),
            Image("keystorage.bin", ree=True, split=(
                Image("keystorage.bin"),
                Image("tail.bin", stage=None), # signerv3
            )),
            Image("keystorage.bin", ree=True, split=(
                Image("keystorage.bin"),
                Image("tail.bin", stage=None), # signerv3
            )),
            Image("ldfw.img", ree=True, split=(
                Image("ldfw.bin"),
                Image("tail.bin", stage=None), # signerv3
            )),
            Image("sboot.bin", ree=True, split=(
                Image("epbl.bin", update_header=True),
                Image("icm.bin", stage=None),
                Image("bl2.bin", ree=True),
                Image("pad.bin", stage=None),
                Image("dpm.img"),
                Image("pad2.bin", stage=None),
                Image("bootload.bin", ree=True, split=(
                    Image("bootload_part1.bin", stage=None),
                    Image("spkg1.bin", ree=True),
                    Image("pad.bin", stage=None),
                    Image("spkg2.bin", ree=True),
                    Image("bootload_part2.bin", stage=None),
                )),
                Image("el3_mon.bin"),
                Image("smap_and_tail.bin", stage=None),#smap+32tag+signerv3
            )),
            Image("ssp.img", stage=None), #idk
            Image("svm.bin"),
            Image("tzar.img", ree=True, split=(
                Image("tzar.bin"),
                Image("tail.bin", stage=None), # signerv3
            )),
            Image("tzsw.img", ree=True, split=(
                Image("tzsw.bin"),
                Image("tail.bin", stage=None), # signerv3
            )),
            Image("uh.bin", ree=True),
            Image("up_param.bin", ree=True),
            Image("vbmeta.img", ree=True),
        )
    )
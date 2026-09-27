# Custom key bootloader guide

This repository can split, patch, and resign bootloader images for some
Exynos SoC's.

Sample usage guide for each SoC to patch and resign images below
Check which files to put to `input` folder from scripts/s5e*.py 

## S5E8890

```bash
python scripts/split.py s5e8890 input output
python scripts/patch_8890.py output/sboot/u-boot.bin
python scripts/build.py s5e8890 keys output
```

Houston payload example:

```bash
python houston-pub/houston.py -e -p payloads/8890_boot_custom_key.bin \
  output/sboot/fwbl1.bin \
  output/sboot/bl31.bin \
  output/sboot/bl2.bin \
  output/sboot/u-boot.bin
```

## S5E9810

```bash
python scripts/split.py s5e9810 input output
python scripts/patch_9810.py output/sboot/u-boot.bin
python scripts/build.py s5e9810 keys output
```

Houston payload example:

```bash
python houston-pub/houston.py -e -p payloads/9810_boot_custom_key.bin \
  output/sboot/fwbl1.bin \
  output/sboot/bl31.bin \
  output/sboot/bl2.bin \
  output/sboot/fwbl1.bin \
  output/sboot/u-boot.bin \
  output/sboot/el3_mon.bin
```

## S5E9840

```bash
python scripts/split.py s5e9840 input output
python scripts/patch_9840.py output/sboot/bootload.bin
python scripts/build.py s5e9840 keys output
```

Houston payload example:

```bash
python houston-pub/houston.py -e -p payloads/9840_boot_custom_key.bin \
  output/sboot/bl1.bin \
  output/sboot/epbl.bin \
  output/sboot/bl2.bin \
  output/sboot/bootload.bin \
  output/sboot/el3_mon.bin \
  output/ldfw/ldfw.bin \
  output/tzsw/tzsw.bin
```

## S5E9945

```bash
python scripts/split.py s5e9945 input output
python scripts/patch_9945.py keys output
python scripts/build.py s5e9945 keys output
```

Not supported by Houston currently.

### Optional key fusing

The patch scripts default to `should_fuse_key = False`. To include the key fusing
patch, set it to `True` in the **matching** `scripts/patch_*.py` file before
running the patch command. The patched bootloader attempts to burn a
free slot for secure boot key after it boots download mode from UFS payload.

**Warning:** Fusing a custom secure boot key is irreversible.
The device will permanently require images signed with the custom key.

## Resources

- [houston-pub](https://github.com/halal-beef/houston-pub)
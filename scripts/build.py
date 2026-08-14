#!/usr/bin/env python3
import importlib
import os
import subprocess
import sys


def sign(
    image_path,
    stage,
    update_header=False,
    ree=False,
    signing_type=0,
    keys_path=None,
    rb_count=None,
):
    if keys_path is None:
        raise ValueError("keys_path is required")

    cmd = [sys.executable, "scripts/sign.py", image_path, keys_path, stage]
    if update_header:
        cmd.append("--update-header")
    if ree:
        cmd += ["--st2-key-type", "1"]
    if rb_count is not None:
        cmd += ["--rb-count", rb_count]
    cmd += ["--signing-type", str(signing_type)]
    subprocess.run(cmd, check=True)


def merge(paths, out_path):
    with open(out_path, "wb") as f:
        for path in paths:
            with open(path, "rb") as part:
                while chunk := part.read(1024 * 1024):
                    f.write(chunk)


def build_image(
    image,
    parent_dir,
    keys_path,
    signing_type,
    rb_count=None,
):
    """Build and sign one image after recursively building its children."""
    image_path = os.path.join(parent_dir, image.name)

    if getattr(image, "split", None):
        parts_dir = os.path.join(parent_dir, os.path.splitext(image.name)[0])

        for child in image.split:
            build_image(
                child,
                parts_dir,
                keys_path,
                signing_type,
                rb_count=rb_count,
            )

        merge(
            [os.path.join(parts_dir, child.name) for child in image.split],
            image_path,
        )

    if image.stage is not None:
        sign(
            image_path,
            stage=image.stage,
            update_header=image.update_header,
            ree=image.ree,
            signing_type=signing_type,
            keys_path=keys_path,
            rb_count=rb_count,
        )

    if image.avb:
        subprocess.run([
            sys.executable, "scripts/avbtool.py", "add_hash_footer",
            "--image", image_path,
            "--partition_name", image.avb,
            "--partition_size", str(image.size),
            "--key", os.path.join(keys_path, "avb.pem"),
            "--algorithm", "SHA256_RSA4096",
            "--salt", "0000000000000000000000000000000000000000000000000000000000000000",
        ], check=True)


def main(argv=None):
    if argv is None:
        argv = sys.argv[1:]
    if len(argv) not in (3, 4):
        print(
            "usage: build.py SOC KEYS_PATH WORK_DIR [RB_COUNT]",
            file=sys.stderr,
        )
        return 2

    soc_name, keys_path, work_dir = argv[:3]
    rb_count = argv[3] if len(argv) == 4 else None
    soc_module = importlib.import_module(soc_name)
    soc = soc_module.soc_data()

    os.makedirs(work_dir, exist_ok=True)
    for image in soc.odin:
        build_image(
            image,
            work_dir,
            keys_path,
            soc.signing_type,
            rb_count=rb_count,
        )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

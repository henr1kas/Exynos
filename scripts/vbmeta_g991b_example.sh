export PATH="$PATH:/home/henr1kas/Desktop/Exynos/otatools/bin"

python scripts/avbtool.py add_hash_footer --image resigned/recovery.img --partition_name recovery --partition_size 67108864 --key keys/avb.pem --algorithm SHA256_RSA4096 --salt 0000000000000000000000000000000000000000000000000000000000000000
python scripts/avbtool.py add_hash_footer --image resigned/dtbo.img --partition_name dtbo --partition_size 8388608 --key keys/avb.pem --algorithm SHA256_RSA4096 --salt 0000000000000000000000000000000000000000000000000000000000000000

python scripts/avbtool.py add_hash_footer --image resigned/boot.img --partition_name boot --partition_size 67108864 --key keys/avb.pem --algorithm SHA256_RSA4096 --salt 0000000000000000000000000000000000000000000000000000000000000000
python scripts/avbtool.py add_hash_footer --image resigned/vendor_boot.img --partition_name vendor_boot --partition_size 67108864 --key keys/avb.pem --algorithm SHA256_RSA4096 --salt 0000000000000000000000000000000000000000000000000000000000000000

python scripts/avbtool.py add_hashtree_footer --hash_algorithm sha256 --image resigned/prism.raw.img --partition_name prism --partition_size 1153433600  --key keys/avb.pem --algorithm SHA256_RSA4096 --salt 0000000000000000000000000000000000000000000000000000000000000000
python scripts/avbtool.py add_hashtree_footer --hash_algorithm sha256 --image resigned/optics.raw.img --partition_name optics --partition_size 31457280 --key keys/avb.pem --algorithm SHA256_RSA4096 --salt 0000000000000000000000000000000000000000000000000000000000000000

python scripts/avbtool.py add_hashtree_footer --hash_algorithm sha256 --image resigned/super/odm.img --partition_name odm --partition_size 4349952 --key keys/avb.pem --algorithm SHA256_RSA4096 --salt 0000000000000000000000000000000000000000000000000000000000000000
python scripts/avbtool.py add_hashtree_footer --hash_algorithm sha256 --image resigned/super/product.img --partition_name product --partition_size 1648754688 --key keys/avb.pem --algorithm SHA256_RSA4096 --salt 0000000000000000000000000000000000000000000000000000000000000000
python scripts/avbtool.py add_hashtree_footer --hash_algorithm sha256 --image resigned/super/system.img --partition_name system --partition_size 7706079232 --key keys/avb.pem --algorithm SHA256_RSA4096 --salt 0000000000000000000000000000000000000000000000000000000000000000
python scripts/avbtool.py add_hashtree_footer --hash_algorithm sha256 --image resigned/super/vendor.img --partition_name vendor --partition_size 1583480832 --key keys/avb.pem --algorithm SHA256_RSA4096 --salt 0000000000000000000000000000000000000000000000000000000000000000

python scripts/avbtool.py make_vbmeta_image \
    --algorithm SHA256_RSA4096 \
    --key keys/avb.pem \
    --include_descriptors_from_image resigned/super/odm.img \
    --include_descriptors_from_image resigned/super/product.img \
    --include_descriptors_from_image resigned/super/system.img \
    --include_descriptors_from_image resigned/super/vendor.img \
    --output vbmeta_system.img

python scripts/avbtool.py make_vbmeta_image \
    --algorithm SHA256_RSA4096 \
    --key keys/avb.pem \
    --chain_partition recovery:6:keys/avb.pubkey \
    --chain_partition dtbo:7:keys/avb.pubkey \
    --chain_partition prism:12:keys/avb.pubkey \
    --chain_partition optics:13:keys/avb.pubkey \
    --prop com.android.build.boot.os_version:11 \
    --prop com.android.build.boot.security_patch:2026-01-01 \
    --prop com.android.build.system.os_version:15 \
    --prop com.android.build.system.security_patch:2026-01-01 \
    --prop com.android.build.vendor.os_version:11 \
    --prop com.android.build.vendor.security_patch:2026-01-01 \
    --include_descriptors_from_image resigned/boot.img \
    --include_descriptors_from_image resigned/vendor_boot.img \
    --include_descriptors_from_image resigned/super/system.img \
    --include_descriptors_from_image resigned/super/vendor.img \
    --include_descriptors_from_image resigned/super/product.img \
    --include_descriptors_from_image resigned/super/odm.img \
    --include_descriptors_from_image resigned/sboot.bin \
    --include_descriptors_from_image resigned/harx.bin \
    --include_descriptors_from_image resigned/keystorage.bin \
    --include_descriptors_from_image resigned/ldfw.img \
    --include_descriptors_from_image resigned/tzsw.img \
    --output vbmeta.img

tail -c 784 resigned/vbmeta.img >> vbmeta.img
tail -c 784 resigned/vbmeta_system.img >> vbmeta_system.img
python scripts/sign.py vbmeta.img keys st2 --st2-key-type 1
python scripts/sign.py vbmeta_system.img keys st2 --st2-key-type 1

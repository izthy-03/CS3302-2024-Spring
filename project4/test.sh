#!/bin/bash
set -x

HIDDEN_FILE="hideme"
ENCRYPTED_FILE="encryptme"
EXEC_FILE="execme"
MOUNT_POINT="/home/izthy/fuse"

make
umount $MOUNT_POINT
./passthrough   --hidden_file_name=$HIDDEN_FILE\
                --encrypted_file_name=$ENCRYPTED_FILE\
                --exec_file_name=$EXEC_FILE\
                $MOUNT_POINT
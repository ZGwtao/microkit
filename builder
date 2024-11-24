#!/usr/bin/env bash
./pyenv/bin/python dev_build.py --rebuild --board qemu_virt_aarch64 --example pd_templates --system-hash 0x79e60a3e13efcb37 --private-key ed25519_private_key.pem --public-key ed25519_public_key.bin

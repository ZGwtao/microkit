#!/usr/bin/env bash
./pyenv/bin/python dev_build.py --rebuild --board qemu_virt_aarch64 --example pd_templates --system-hash 0xfbe7b4c7b22a3ab9 --private-key ed25519_private_key.pem --public-key ed25519_public_key.bin

#!/usr/bin/env python3

import argparse
import struct
import sys
import binascii
import lief
import os
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.backends import default_backend

def parse_arguments():
    parser = argparse.ArgumentParser(description="Patch an ELF file by adding an access rights table with an Ed25519 asymmetric signature.")
    parser.add_argument("elf_file", help="Path to the input ELF file.")
    parser.add_argument("system_hash", help="System hash in hexadecimal (uint64).")
    parser.add_argument("-o", "--output", help="Path to the output patched ELF file. If not specified, '_patched' will be appended to the input filename.")
    parser.add_argument("-k", "--private-key", required=True, help="Path to the Ed25519 private key in PEM format for signing.")
    return parser.parse_args()

def prompt_for_ids(prompt_message):
    while True:
        user_input = input(prompt_message).strip()
        if not user_input:
            return []
        try:
            # Split by comma and convert to integers
            ids = [int(x.strip(), 0) for x in user_input.split(",") if x.strip()]
            return ids
        except ValueError:
            print("Invalid input. Please enter comma-separated integers (e.g., 1, 2, 3).")

def prompt_for_vaddrs(prompt_message):
    while True:
        user_input = input(prompt_message).strip()
        if not user_input:
            return []
        try:
            # Split by comma and convert to integers (hexadecimal)
            vaddrs = [int(x.strip(), 16) for x in user_input.split(",") if x.strip()]
            return vaddrs
        except ValueError:
            print("Invalid input. Please enter comma-separated hexadecimal addresses (e.g., 0x1000, 0x2000).")

def encode_access_rights(channel_ids, irq_ids, memory_vaddrs):
    access_rights = []
    TYPE_CHANNEL = 0x01
    TYPE_IRQ = 0x02
    TYPE_MEMORY = 0x03

    # Encode Channel IDs
    for cid in channel_ids:
        # '<BQ' -> Little endian, unsigned char (1 byte), unsigned long long (8 bytes)
        entry = struct.pack("<BQ", TYPE_CHANNEL, cid)
        access_rights.append(entry)

    # Encode IRQ IDs
    for irq in irq_ids:
        entry = struct.pack("<BQ", TYPE_IRQ, irq)
        access_rights.append(entry)

    # Encode Memory Virtual Addresses
    for vaddr in memory_vaddrs:
        entry = struct.pack("<BQ", TYPE_MEMORY, vaddr)
        access_rights.append(entry)

    return b"".join(access_rights)

def create_access_rights_section(system_hash, access_rights_encoded, private_key_path):
    # Pack system hash as uint64 (8 bytes) in little endian
    system_hash_packed = struct.pack("<Q", system_hash)

    # Number of access rights as uint32 (4 bytes) in little endian
    num_access_rights = len(access_rights_encoded) // 9  # Each entry is 9 bytes
    num_access_rights_packed = struct.pack("<I", num_access_rights)

    # Combine all parts
    data = system_hash_packed + num_access_rights_packed + access_rights_encoded

    # Load the private key
    try:
        with open(private_key_path, "rb") as key_file:
            private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=None,
                backend=default_backend()
            )
            if not isinstance(private_key, ed25519.Ed25519PrivateKey):
                print("Error: The provided key is not an Ed25519 private key.")
                sys.exit(1)
    except Exception as e:
        print(f"Error loading private key: {e}")
        sys.exit(1)

    # Sign the data using Ed25519
    try:
        signature = private_key.sign(data)
    except Exception as e:
        print(f"Error signing data: {e}")
        sys.exit(1)
        
    print(f"Signature (hex): {signature.hex()}")
    print(f"Message (hex): {data.hex()}")
    print(f"Private key (hex): {private_key.private_bytes_raw().hex()}")

    # Combine signature and data as signature || data
    print(f"Data to be signed: {data}")
    print(f"System hash: 0x{system_hash:x}")
    print(f"No. of access rights: {num_access_rights}")
    print(f"Length of data: {len(data)} bytes")
    print(f"Length of signature: {len(signature)} bytes")
    
    section_content = signature + data  # Signature comes first
    return section_content

def add_section_to_elf(input_elf_path, output_elf_path, section_name, section_content):
    # Parse the ELF binary
    binary = lief.parse(input_elf_path)
    if binary is None:
        print(f"Error: Failed to parse ELF file '{input_elf_path}'.")
        sys.exit(1)

    # Check if section already exists
    if binary.get_section(section_name):
        print(f"Error: Section '{section_name}' already exists in '{input_elf_path}'.")
        sys.exit(1)

    # Create a new section
    new_section = lief.ELF.Section(section_name)
    new_section.content = list(section_content)
    new_section.size = len(section_content)
    new_section.type = lief.ELF.Section.TYPE.PROGBITS
    new_section.flags = lief.ELF.Section.FLAGS.ALLOC

    # Add the section to the ELF binary
    binary.add(new_section, loaded=True)

    # Write the modified ELF to the output path
    binary.write(output_elf_path)

def main():
    args = parse_arguments()

    input_elf = args.elf_file
    system_hash_hex = args.system_hash
    output_elf = args.output
    private_key_path = args.private_key

    # Determine output file name if not provided
    if not output_elf:
        base, ext = os.path.splitext(input_elf)
        output_elf = f"{base}_patched{ext if ext else '.elf'}"

    # Convert system hash from hex to uint64
    try:
        system_hash = int(system_hash_hex, 16)
        if system_hash < 0 or system_hash > 0xFFFFFFFFFFFFFFFF:
            raise ValueError
    except ValueError:
        print("Error: System hash must be a valid 64-bit hexadecimal number (e.g., 0x1A2B3C4D5E6F7890).")
        sys.exit(1)

    # Check if private key file exists
    if not os.path.isfile(private_key_path):
        print(f"Error: Private key file '{private_key_path}' does not exist.")
        sys.exit(1)

    print(f"=== Configuring access rights for ELF file '{input_elf}' ===")
    print("Enter ids (for channels and irq) or vaddrs in hex (for mappings) as comma-separated values. Leave empty to skip a category.")

    # Prompt for Channel IDs
    channel_ids = prompt_for_ids("Enter channel ids to grant access to (e.g. 1, 2, 3): ")

    # Prompt for IRQ IDs
    irq_ids = prompt_for_ids("Enter irq ids to grant access to (e.g. 10, 20, 30): ")

    # Prompt for Memory Virtual Addresses
    memory_vaddrs = prompt_for_vaddrs("Enter mapping vaddrs to grant access to (hexadecimal, e.g. 0x1000, 0x2000): ")

    # Encode access rights
    access_rights_encoded = encode_access_rights(channel_ids, irq_ids, memory_vaddrs)

    # Create section content with signature
    section_content = create_access_rights_section(system_hash, access_rights_encoded, private_key_path)
    print(f"Section content length (with signature): {len(section_content)} bytes")

    # Add the new section to the ELF file
    section_name = ".access_rights"
    add_section_to_elf(input_elf, output_elf, section_name, section_content)
    print(f"Successfully added section '{section_name}' to '{output_elf}'.")

    print(f"Access rights section signed with Ed25519 using the provided private key.")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nOperation cancelled by user.")
        sys.exit(0)

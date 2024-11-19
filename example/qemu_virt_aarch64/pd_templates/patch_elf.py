#!/usr/bin/env python3

import argparse
import struct
import sys
import binascii
import lief

def parse_arguments():
    parser = argparse.ArgumentParser(description="Patch an ELF file by adding an access rights table.")
    parser.add_argument("elf_file", help="Path to the input ELF file.")
    parser.add_argument("system_hash", help="System hash in hexadecimal (uint64).")
    parser.add_argument("-o", "--output", help="Path to the output patched ELF file. If not specified, '_patched' will be appended to the input filename.")
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

    print(memory_vaddrs)
    # Encode Memory Virtual Addresses
    for vaddr in memory_vaddrs:
        entry = struct.pack("<BQ", TYPE_MEMORY, vaddr)
        access_rights.append(entry)

    return b"".join(access_rights)

def create_access_rights_section(system_hash, access_rights_encoded):
    # Pack system hash as uint64 (8 bytes) in little endian
    system_hash_packed = struct.pack("<Q", system_hash)

    # Number of access rights as uint32 (4 bytes) in little endian
    num_access_rights = len(access_rights_encoded) // 9  # Each entry is 9 bytes
    num_access_rights_packed = struct.pack("<I", num_access_rights)

    # Combine all parts
    section_content = system_hash_packed + num_access_rights_packed + access_rights_encoded
    return section_content

def add_section_to_elf(input_elf_path, output_elf_path, section_name, section_content):
    # Parse the ELF binary
    binary = lief.parse(input_elf_path)
    if binary is None:
        print(f"Error: Failed to parse ELF file '{input_elf_path}'.")
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
    print(f"Successfully added section '{section_name}' to '{output_elf_path}'.")

def main():
    args = parse_arguments()

    input_elf = args.elf_file
    system_hash_hex = args.system_hash
    output_elf = args.output

    # Determine output file name if not provided
    if not output_elf:
        if input_elf.lower().endswith(".elf"):
            output_elf = input_elf[:-4] + "_patched.elf"
        else:
            output_elf = input_elf + "_patched.elf"

    # Convert system hash from hex to uint64
    try:
        system_hash = int(system_hash_hex, 16)
        if system_hash < 0 or system_hash > 0xFFFFFFFFFFFFFFFF:
            raise ValueError
    except ValueError:
        print("Error: System hash must be a valid 64-bit hexadecimal number (e.g., 0x1A2B3C4D5E6F7890).")
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

    # Create section content
    section_content = create_access_rights_section(system_hash, access_rights_encoded)
    print(section_content)

    # Add the new section to the ELF file
    section_name = ".access_rights"
    add_section_to_elf(input_elf, output_elf, section_name, section_content)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nOperation cancelled by user.")
        sys.exit(0)

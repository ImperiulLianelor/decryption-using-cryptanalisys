import collections
import sys
import os
import binascii

def decrypt_caesar(data, shift):
    """
    Decrypt data using Caesar cipher with the given shift.
    Each byte value is shifted by the amount specified.
    """
    decrypted = bytearray()
    for byte in data:
        # Apply the shift to each byte value (modulo 256 to keep within byte range)
        decrypted_byte = (byte - shift) % 256
        decrypted.append(decrypted_byte)
    return bytes(decrypted)

def get_common_file_signatures():
    """
    Returns a dictionary of common file signatures (magic numbers) with their corresponding file types.
    """
    signatures = {
        # Image formats
        b'\xff\xd8\xff': 'JPG',
        b'\x89PNG\r\n\x1a\n': 'PNG',
        b'BM': 'BMP',
        
        # Video formats
        b'\x00\x00\x00\x18\x66\x74\x79\x70\x33\x67\x70': '3GP',
        b'RIFF': 'AVI',
        b'\x00\x00\x00\x1c\x66\x74\x79\x70\x6d\x70\x34\x32': 'MP4',
        
        # Document formats
        b'%PDF': 'PDF',
        b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1': 'DOC/XLS/PPT', # Old Office formats
        b'PK\x03\x04': 'DOCX/XLSX/PPTX/ZIP', # New Office formats
        
        # Audio formats
        b'ID3': 'MP3',
        
        # Archive formats
        b'\x1f\x8b\x08': 'TAR.GZ',
        
        # Executable
        b'MZ': 'EXE'
    }
    return signatures

def identify_file_type(data):
    """
    Identify file type based on its signature (magic numbers).
    """
    signatures = get_common_file_signatures()
    
    for signature, filetype in signatures.items():
        # Check if the file starts with this signature
        if data.startswith(signature):
            return filetype
    
    # If nothing matched
    return 'Unknown'

def frequency_analysis(data):
    """
    Perform frequency analysis on the bytes in the data.
    Returns the most common byte values.
    """
    counter = collections.Counter(data)
    return counter.most_common(10)  # Return top 10 most common bytes

def attempt_all_shifts(encrypted_data):
    """
    Try all possible shifts (0-255) and look for known file signatures
    in the decrypted data.
    """
    signatures = get_common_file_signatures()
    results = []
    
    for shift in range(256):
        decrypted = decrypt_caesar(encrypted_data, shift)
        
        # Check if the decrypted data starts with any known file signature
        for signature, filetype in signatures.items():
            if decrypted.startswith(signature):
                results.append((shift, filetype))
                break
    
    return results

def main():
    if len(sys.argv) < 2:
        print("Usage: python decrypt_caesar.py <encrypted_file>")
        return
    
    encrypted_file = sys.argv[1]
    
    try:
        with open(encrypted_file, 'rb') as f:
            encrypted_data = f.read()
        
        # First, let's print some information about the encrypted file
        print(f"Encrypted file size: {len(encrypted_data)} bytes")
        print(f"First 20 bytes (hex): {encrypted_data[:20].hex(' ')}")
        
        # Perform frequency analysis
        print("\nFrequency Analysis (Top 10 most common bytes):")
        for byte, count in frequency_analysis(encrypted_data):
            print(f"Byte {byte} (hex: {byte:02x}): {count} occurrences")
        
        # Try all possible shifts and look for known file signatures
        print("\nTrying all possible shifts (0-255)...")
        results = attempt_all_shifts(encrypted_data)
        
        if results:
            print("\nPotential matches found:")
            for shift, filetype in results:
                print(f"Shift value: {shift}, File type: {filetype}")
                
                # Save the decrypted file for the first match (or you can save all)
                decrypted = decrypt_caesar(encrypted_data, shift)
                output_file = f"{encrypted_file}_decrypted_shift_{shift}.{filetype.lower().split('/')[0]}"
                with open(output_file, 'wb') as f:
                    f.write(decrypted)
                print(f"Decryped file saved as: {output_file}")
        else:
            print("\nNo known file signatures found in any shift. Trying brute force approach...")
            
            # If no matches found, save a few decrypted versions for manual inspection
            for shift in range(256):
                # We'll only save a few candidates to avoid creating too many files
                if shift % 32 == 0:  # Save every 32nd shift (0, 32, 64, 96, 128, 160, 192, 224)
                    decrypted = decrypt_caesar(encrypted_data, shift)
                    output_file = f"{encrypted_file}_decrypted_shift_{shift}.bin"
                    with open(output_file, 'wb') as f:
                        f.write(decrypted)
                    print(f"Decrypted with shift {shift} saved as: {output_file}")
    
    except FileNotFoundError:
        print(f"Error: File '{encrypted_file}' not found.")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    main()


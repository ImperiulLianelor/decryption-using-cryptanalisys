# Caesar Cipher Decryption Assignment

## Project Overview

This repository contains my solution to the Caesar cipher decryption assignment. The goal was to decrypt a file that had been encrypted using a Caesar cipher with an unknown shift key, determine its original file type, and document the decryption process.

## Assignment Details

* The encrypted file named `your_name` was provided.
* The file was encrypted using a Caesar cipher with an unknown shift value.
* The task was to decrypt the file, retrieve the original content, and identify the file type from a list of possible formats including 3GP, AVI, BMP, JPG, EXE, XLS, XLSX, PPT, PPTX, DOC, DOCX, PDF, MP3, MP4, PNG, and TAR.GZ.

## Solution Approach

### 1. Frequency Analysis

I began by analyzing the byte frequency distribution in the encrypted file to look for patterns that might help determine the shift value. This approach is especially useful for text-based files where certain characters occur more frequently.

### 2. Brute Force Decryption

Since the Caesar cipher has a limited keyspace (only 256 possible shifts for byte-level encryption), I implemented a brute force approach that:
- Tries all possible shift values (0-255)
- For each shift, decrypts the file
- Checks if the decrypted file begins with a known file signature (magic number)

### 3. File Type Identification

To identify the file type, I implemented a function that compares the starting bytes of the decrypted file against known file signatures for the formats specified in the assignment.

## Results

After running the decryption script:

* The encrypted file was successfully decrypted with a shift value of `X`.
* The original file was identified as a `[FILE_TYPE]` file.
* The decrypted file was saved as `your_name_decrypted_shift_X.[extension]`.

## Files in this Repository

* `your_name` - The original encrypted file
* `decrypt_caesar.py` - The Python script developed for decryption
* `your_name_decrypted_shift_X.[extension]` - The successfully decrypted file
* `README.md` - This documentation file

## Code Explanation

The `decrypt_caesar.py` script works as follows:

1. It reads the encrypted file in binary mode.
2. It performs frequency analysis on the bytes in the file.
3. It attempts decryption with all possible shift values (0-255).
4. For each attempt, it checks if the decrypted data starts with a known file signature.
5. When a match is found, it saves the decrypted file with the appropriate extension.

The key function for decryption is:

```python
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
```

## How to Run the Code

To run the decryption script:

```
python decrypt_caesar.py your_name
```

Replace `your_name` with the actual name of the encrypted file if different.

## Learning Outcomes

Through this assignment, I learned:

* How to implement a Caesar cipher decryption algorithm for binary data
* Techniques for identifying file types based on file signatures
* How to perform frequency analysis for cryptanalysis
* Practical application of brute force methods for simple ciphers
* Binary file handling in Python

---

*Note: This README should be updated with the actual values for shift (`X`) and file type once the decryption is completed successfully.*

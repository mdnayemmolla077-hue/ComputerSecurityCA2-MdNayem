# ComputerSecurityCA2-MdNayem

Author: Md Nayem Molla

## Files
- AesCryptFile.java  — Java source file
- README.md

## Requirements
- Java JDK 8+ installed

## Compile
javac AesCryptFile.java

## Run
java AesFileCrypt

## Usage
1. Choose option 1 to encrypt a file. Input a filename 
2. The program writes `ciphertext.txt` (Base64 of IV + ciphertext) and prints the key (Base64) to the console.
3. Choose option 2 to decrypt. Input `ciphertext.txt` and paste the Base64 key. The program writes `plaintext.txt`.

## Notes / Validation
- Program validates file existence and key format. It prints friendly messages on error.
- AES/CBC/PKCS5Padding used. Key printed in Base64 

## Testing
Included sample file: plaintext.txt (optional)


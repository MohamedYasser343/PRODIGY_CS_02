# PRODIGY_CS_02
A Python-based application for encrypting and decrypting images using custom algorithms with a graphical user interface (GUI).

## Features
- Two encryption algorithms: Basic and Advanced
- Configurable encryption rounds (1-5)
- Key-based encryption using either text input or file content
- GUI with progress bar and operation history
- Supports common image formats (PNG, JPG, BMP)
- Threaded processing to maintain UI responsiveness
- Logging of all operations

## Requirements
- Python 3.6+
- Required packages:
  - Pillow (PIL)
  - numpy
  - tqdm
  - tkinter (usually included with Python)
 
## Technical Details
### Encryption Process
- Uses SHA-256 hash of key to generate random seed
- Applies XOR operation with generated keys
- Performs pixel position shuffling
- Advanced mode includes additional array rolling
- Multiple rounds of encryption supported
### Classes
- `ImageEncryptor`: Core encryption/decryption logic
- `ImageEncryptorGUI`: Tkinter-based graphical interface
### Key Features
- Thread-safe processing
- Progress bar updates
- Error handling and logging
- Operation history tracking

## Security Notes
- This is an educational tool, not intended for production security needs
- Encryption strength depends on key quality and the number of rounds
- Advanced algorithm adds complexity but is not cryptographically proven

## Logging
- All operations are logged to `image_encryptor.log`
- Includes timestamps and success/failure status
- Viewable in the History tab

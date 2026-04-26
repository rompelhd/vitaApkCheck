# vitaApkCheck

Python script to analyze an Android APK file to help determine whether a game is a good candidate for porting to the PlayStation Vita.

## Requirements

- Python 3.x
- pyaxmlparser (used for APK parsing)
- VitaSDK

Install Python dependency with:
pip install pyaxmlparser

> Note: Standard Python libraries (os, sys, zipfile, etc.) are already included with Python and do not need to be installed.

## Note

This script assumes that VitaSDK is properly installed and configured.

- **Windows:**  
  VitaSDK should be installed via MSYS2 at:  
  `C:\msys64\usr\local\vitasdk\`

- **Linux:**  
  VitaSDK must be installed and available in your environment.  
  The `VITASDK` environment variable should be set and its tools accessible from your `PATH`.

## Usage

python3 vitaApkCheck.py <apk_file_or_directory>

The script will analyze the APK and display the results.

## Example Output

<img width="651" height="719" alt="image" src="https://github.com/user-attachments/assets/6c966d19-5c1a-4e24-b76a-888b3cdd6cd3" />

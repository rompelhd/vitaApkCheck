import os
import fnmatch
import math
import shutil
import subprocess
import sys
from zipfile import ZipFile
from pyaxmlparser import APK

APK_PATTERN = "*.apk"
SO_PATTERN = "*.so"

IS_WINDOWS = os.name == "nt"

if IS_WINDOWS:
	# Where to find the VITA_SDK binaries needed to examine elf files
    BIN_DIRECTORY = r"C:\msys64\usr\local\vitasdk\arm-vita-eabi\bin"
    READ_ELF_PATH = os.path.join(BIN_DIRECTORY, "readelf.exe")
    OBJDUMP_PATH = os.path.join(BIN_DIRECTORY, "objdump.exe")
else:
	# Linux has it in the PATH, right?
    READ_ELF_PATH = shutil.which("readelf") or "readelf"
    OBJDUMP_PATH = shutil.which("objdump") or "objdump"

# Just some search strings
FINDSTR_JC_STRING = "Java_"
FINDSTR_OPENSLES_STRINGS = [
    "SL_IID_ANDROIDEFFECT",
    "SL_IID_ANDROIDEFFECTCAPABILITIES",
    "SL_IID_ANDROIDEFFECTSEND",
    "SL_IID_ANDROIDCONFIGURATION",
    "SL_IID_ANDROIDSIMPLEBUFFERQUEUE",
]

# Terminal colors
x = "\033[0m"
gr = "\033[90m"
lr = "\033[91m"
lg = "\033[92m"
ly = "\033[93m"
mg = "\033[95m"
cy = "\033[96m"
w = "\033[97m"

def convert_size(size_bytes: int) -> str:
    if size_bytes == 0:
        return "0B"
    size_name = ("B", "KB", "MB", "GB", "TB", "PB", "EB", "ZB", "YB")
    i = int(math.floor(math.log(size_bytes, 1024)))
    p = math.pow(1024, i)
    s = round(size_bytes / p, 2)
    return f"{s} {size_name[i]}"


def run_command(cmd):
    p = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )
    out, err = p.communicate()
    return out.decode(errors="ignore"), err.decode(errors="ignore"), p.returncode


def run_readelf_dynamic(path: str) -> str:
    out, _, _ = run_command([READ_ELF_PATH, "-d", path])
    return out


def run_objdump_symbols(path: str) -> str:
    out, _, _ = run_command([OBJDUMP_PATH, "-T", "-C", path])
    return out


def extract_file_from_zip(zip_archive: ZipFile, member_name: str, out_path: str):
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    with zip_archive.open(member_name) as src, open(out_path, "wb") as dst:
        shutil.copyfileobj(src, dst)


def parse_needed_libs(readelf_text: str):
    libs = []
    for line in readelf_text.splitlines():
        if "NEEDED" in line:
            l = line.find("[")
            r = line.find("]", l + 1)
            if l != -1 and r != -1 and r > l + 1:
                libs.append(line[l + 1:r])
    return libs


def extract_java_symbols_from_objdump(objdump_text: str):
    symbols = []
    for line in objdump_text.splitlines():
        idx = line.find(FINDSTR_JC_STRING)
        if idx != -1:
            symbols.append(line[idx:].strip())
    return symbols


def detect_opensles_symbols(objdump_text: str):
    found = []
    for sym in FINDSTR_OPENSLES_STRINGS:
        if sym in objdump_text:
            found.append(sym)
    return found


def list_apks(path: str):
    if os.path.isfile(path):
        return os.path.dirname(path), [os.path.basename(path)]
    if os.path.isdir(path):
        files = os.listdir(path)
        return path, fnmatch.filter(files, APK_PATTERN)
    return None, []

def check_apk(check_apk_path: str):
    source_folder, apk_files = list_apks(check_apk_path)

    if not source_folder and not apk_files:
        print("An error has occurred. Invalid path.")
        return

    if not apk_files:
        print("No APK files found.")
        return

    for apk_file in apk_files:
        apk_path = os.path.join(source_folder, apk_file)
        apk_file_name, _ = os.path.splitext(os.path.basename(apk_path))

        print(f"{gr}#########################################{x}")
        print(f"APK: {lg}{apk_path}{x}")

        possible_port_has_armv7 = False
        possible_port_has_armv6 = False
        possible_port_has_unity = False
        possible_port_has_gdx = False
        possible_port_has_glesv3 = False

        port_verdict = "Possible"
        port_verdict_reason_list = []

        try:
            apk_info = APK(apk_path)
            if apk_info:
                print(f"Name: {lg}{apk_info.application}{x}")
                print(f"Package: {lg}{apk_info.package}{x}")
                print(f"Version: {lg}{apk_info.version_name}{x}")
                print(f"Code: {lg}{apk_info.version_code}{x}")

            with ZipFile(apk_path) as zip_archive:
                print("Checking libs")

                so_candidates_v7 = []
                so_candidates_v6 = []
                za_lib_list = []

                for file_name in zip_archive.namelist():
                    if not file_name.startswith("lib"):
                        continue

                    za_lib_list.append(file_name)
                    file_size = convert_size(zip_archive.getinfo(file_name).file_size)

                    if "libunity" in file_name:
                        print(f"...{lr}{file_name}...{file_size}{x}")
                        possible_port_has_unity = True
                        port_verdict_reason_list.append("Found libunity")
                    elif "libgdx" in file_name:
                        print(f"...{lr}{file_name}...{file_size}{x}")
                        possible_port_has_gdx = True
                        port_verdict_reason_list.append("Found libgdx")
                    else:
                        print(f"...{cy}{file_name}...{file_size}{x}")

                    if "armeabi-v7a" in file_name:
                        possible_port_has_armv7 = True
                        if file_name.endswith(".so"):
                            so_candidates_v7.append(file_name)
                    elif "lib/armeabi/" in file_name:
                        possible_port_has_armv6 = True
                        if file_name.endswith(".so"):
                            so_candidates_v6.append(file_name)

                if not possible_port_has_armv7 and not possible_port_has_armv6:
                    port_verdict_reason_list.append("Didn't find armeabi-v7a or armeabi")
                    port_verdict = "Unportable"

                selected_so_members = so_candidates_v7 if so_candidates_v7 else so_candidates_v6
                extracted_so_paths = []

                if selected_so_members:
                    out_dir = os.path.join(source_folder, apk_file_name)
                    for member in selected_so_members:
                        out_path = os.path.join(out_dir, os.path.basename(member))
                        extract_file_from_zip(zip_archive, member, out_path)
                        extracted_so_paths.append(out_path)

            for so_path in extracted_so_paths:
                so_file = os.path.basename(so_path)
                print(f"Checking {lg}{so_file}{x}")

                readelf_output = run_readelf_dynamic(so_path)
                needed_lib_list = parse_needed_libs(readelf_output)

                if needed_lib_list:
                    print(f"...Found the following {mg}NEEDED{x} libs")
                    for lib_string in needed_lib_list:
                        print(f"......{lib_string}")
                        if "libGLESv3" in lib_string:
                            possible_port_has_glesv3 = True
                            if port_verdict != "Unportable":
                                port_verdict = "Maybe possible"
                                port_verdict_reason_list.append("Found libGLESv3")

                objdump_output = run_objdump_symbols(so_path)

                # Java_ symbols
                java_symbols = extract_java_symbols_from_objdump(objdump_output)
                java_count = len(java_symbols)
                if java_count:
                    print(f"...Found {mg}{java_count} Java_com{x} functions")
                    if java_count >= 100 and port_verdict != "Unportable":
                        port_verdict = "Maybe possible"
                        port_verdict_reason_list.append("Found large number of Java reqs")

                    for sym in java_symbols:
                        print(f"......{cy}{sym}{x}")

                # OpenSLES symbols (except fmod)
                if "fmod" not in so_file.lower():
                    found_opensles = detect_opensles_symbols(objdump_output)
                    if found_opensles:
                        for sym in found_opensles:
                            print(f"...Found {lr}{sym}{x} symbol")
                        if "Found unsupported opensles symbols" not in port_verdict_reason_list:
                            port_verdict_reason_list.append("Found unsupported opensles symbols")
                        port_verdict = "Unportable"

            if possible_port_has_armv7 and not possible_port_has_unity and not possible_port_has_glesv3 and not possible_port_has_gdx:
                print(f"...{lg}POSSIBLE PORT{x}")
            else:
                print(f"...{lr}UNABLE TO BE PORTED{x}")

            if port_verdict_reason_list:
                print(f"{ly}Verdict detail: {port_verdict}{x}")
                for r in port_verdict_reason_list:
                    print(f"{ly}- {r}{x}")
            else:
                print(f"{ly}Verdict detail: {port_verdict}{x}")

        except Exception as error:
            print(f"{error}")


if __name__ == "__main__":
    if len(sys.argv) == 2:
        check_apk(sys.argv[1])
    else:
        print("First argument should be an APK or folder with APKs")

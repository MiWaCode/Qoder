import os
import sys
import time
import threading
import uuid
import ctypes
import typing
from ctypes import wintypes

# Color codes for Windows console
class Colors:
    RESET = '\033[0m'
    BOLD = '\033[1m'
    
    # Foreground colors
    BLACK = '\033[30m'
    RED = '\033[31m'
    GREEN = '\033[32m'
    YELLOW = '\033[33m'
    BLUE = '\033[34m'
    MAGENTA = '\033[35m'
    CYAN = '\033[36m'
    WHITE = '\033[37m'
    
    # Bright colors
    BRIGHT_BLACK = '\033[90m'
    BRIGHT_RED = '\033[91m'
    BRIGHT_GREEN = '\033[92m'
    BRIGHT_YELLOW = '\033[93m'
    BRIGHT_BLUE = '\033[94m'
    BRIGHT_MAGENTA = '\033[95m'
    BRIGHT_CYAN = '\033[96m'
    BRIGHT_WHITE = '\033[97m'
    
    # Background colors
    BG_BLACK = '\033[40m'
    BG_RED = '\033[41m'
    BG_GREEN = '\033[42m'
    BG_YELLOW = '\033[43m'
    BG_BLUE = '\033[44m'
    BG_MAGENTA = '\033[45m'
    BG_CYAN = '\033[46m'
    BG_WHITE = '\033[47m'

# Enable ANSI escape sequences on Windows
def enable_ansi_colors():
    try:
        import ctypes
        kernel32 = ctypes.windll.kernel32
        kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
        return True
    except:
        return False

# Initialize colors
enable_ansi_colors()


PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010
PROCESS_VM_WRITE = 0x0020
PROCESS_VM_OPERATION = 0x0008
TH32CS_SNAPPROCESS = 0x00000002

MAX_PATH = 260


kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
psapi = ctypes.WinDLL('psapi', use_last_error=True)


class PROCESSENTRY32W(ctypes.Structure):
    _fields_ = [
        ("dwSize", wintypes.DWORD),
        ("cntUsage", wintypes.DWORD),
        ("th32ProcessID", wintypes.DWORD),
        ("th32DefaultHeapID", ctypes.c_size_t),
        ("th32ModuleID", wintypes.DWORD),
        ("cntThreads", wintypes.DWORD),
        ("th32ParentProcessID", wintypes.DWORD),
        ("pcPriClassBase", ctypes.c_long),
        ("dwFlags", wintypes.DWORD),
        ("szExeFile", wintypes.WCHAR * MAX_PATH),
    ]


OpenProcess = kernel32.OpenProcess
OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
OpenProcess.restype = wintypes.HANDLE

CloseHandle = kernel32.CloseHandle
CloseHandle.argtypes = [wintypes.HANDLE]
CloseHandle.restype = wintypes.BOOL

CreateToolhelp32Snapshot = kernel32.CreateToolhelp32Snapshot
CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
CreateToolhelp32Snapshot.restype = wintypes.HANDLE

Process32FirstW = kernel32.Process32FirstW
Process32FirstW.argtypes = [wintypes.HANDLE, ctypes.POINTER(PROCESSENTRY32W)]
Process32FirstW.restype = wintypes.BOOL

Process32NextW = kernel32.Process32NextW
Process32NextW.argtypes = [wintypes.HANDLE, ctypes.POINTER(PROCESSENTRY32W)]
Process32NextW.restype = wintypes.BOOL

QueryFullProcessImageNameW = kernel32.QueryFullProcessImageNameW
QueryFullProcessImageNameW.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD)]
QueryFullProcessImageNameW.restype = wintypes.BOOL

EnumProcessModules = psapi.EnumProcessModules
EnumProcessModules.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.HMODULE), wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
EnumProcessModules.restype = wintypes.BOOL

ReadProcessMemory = kernel32.ReadProcessMemory
ReadProcessMemory.argtypes = [wintypes.HANDLE, wintypes.LPCVOID, wintypes.LPVOID, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
ReadProcessMemory.restype = wintypes.BOOL

WriteProcessMemory = kernel32.WriteProcessMemory
WriteProcessMemory.argtypes = [wintypes.HANDLE, wintypes.LPVOID, wintypes.LPCVOID, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
WriteProcessMemory.restype = wintypes.BOOL


class ProcessInfo:
    def __init__(self, pid: int, name: str, path: str, base_address: int):
        self.pid = pid
        self.name = name
        self.path = path
        self.base_address = base_address
        self.machine_id_address = 0


def is_user_space_address(address: int) -> bool:
    return address < 0x7FFFFFFF0000


def widechar_buffer(length: int):
    return ctypes.create_unicode_buffer(length)


def get_process_full_path(h_process) -> str:
    buf_len = wintypes.DWORD(MAX_PATH)
    buf = widechar_buffer(buf_len.value)
    if QueryFullProcessImageNameW(h_process, 0, buf, ctypes.byref(buf_len)):
        return buf.value
    return ""


def get_process_base_address(h_process) -> int:
    arr_hmods = (wintypes.HMODULE * 1024)()
    needed = wintypes.DWORD(0)
    if not EnumProcessModules(h_process, arr_hmods, ctypes.sizeof(arr_hmods), ctypes.byref(needed)):
        return 0
    if needed.value == 0:
        return 0
    mod = arr_hmods[0]
    addr = getattr(mod, 'value', None)
    if addr is None:
        try:
            addr = int(mod)
        except Exception:
            return 0
    try:
        return int(addr)
    except Exception:
        return 0


def get_qoder_processes() -> list:
    processes = []
    h_snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if h_snapshot == wintypes.HANDLE(-1).value:
        return processes

    try:
        pe = PROCESSENTRY32W()
        pe.dwSize = ctypes.sizeof(PROCESSENTRY32W)
        if not Process32FirstW(h_snapshot, ctypes.byref(pe)):
            return processes
        while True:
            name = pe.szExeFile.lower()
            if name == 'qoder.exe':
                h_proc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pe.th32ProcessID)
                if h_proc:
                    try:
                        full_path = get_process_full_path(h_proc)
                        lower_path = full_path.lower()
                        if all(k in lower_path for k in ["bin", "resources"]) and any(k in lower_path for k in ["x86", "x64", "x86_64"]):
                            base_addr = get_process_base_address(h_proc)
                            processes.append(ProcessInfo(pe.th32ProcessID, name, full_path, base_addr))
                    finally:
                        CloseHandle(h_proc)
            if not Process32NextW(h_snapshot, ctypes.byref(pe)):
                break
    finally:
        CloseHandle(h_snapshot)
    return processes


USE_POINTER = True
MODULE_RELATIVE_OFFSET = 0x5e87b90


def read_pointer_value(h_process, address: int) -> int:
    ptr_size = ctypes.sizeof(ctypes.c_void_p)
    if ptr_size == 8:
        val = ctypes.c_uint64(0)
    else:
        val = ctypes.c_uint32(0)
    bytes_read = ctypes.c_size_t(0)
    if not ReadProcessMemory(h_process, ctypes.c_void_p(address), ctypes.byref(val), ctypes.sizeof(val), ctypes.byref(bytes_read)):
        return 0
    return int(val.value)


def read_memory(h_process, address: int, size: int) -> bytes:
    buf = (ctypes.c_ubyte * size)()
    bytes_read = ctypes.c_size_t(0)
    if not ReadProcessMemory(h_process, ctypes.c_void_p(address), buf, size, ctypes.byref(bytes_read)):
        return b""
    return bytes(buf[: bytes_read.value])


def write_memory(h_process, address: int, data: bytes) -> bool:
    size = len(data)
    buf = (ctypes.c_ubyte * size).from_buffer_copy(data)
    bytes_written = ctypes.c_size_t(0)
    return bool(WriteProcessMemory(h_process, ctypes.c_void_p(address), buf, size, ctypes.byref(bytes_written)) and bytes_written.value == size)


def set_machine_id_address(process: ProcessInfo) -> bool:
    h_proc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, process.pid)
    if not h_proc:
        return False
    try:
        if not USE_POINTER:
            if process.base_address and is_user_space_address(process.base_address):
                process.machine_id_address = process.base_address
                return True
            return False

        if not process.base_address:
            return False
            
        pointer_address = int(process.base_address) + MODULE_RELATIVE_OFFSET
        if not is_user_space_address(pointer_address):
            return False
            
        machine_id_address = read_pointer_value(h_proc, pointer_address)
        if not machine_id_address or not is_user_space_address(machine_id_address):
            return False
            
        process.machine_id_address = machine_id_address
        return True
    finally:
        CloseHandle(h_proc)

def modify_machine_id(process: ProcessInfo, new_machine_id: str) -> bool:
    h_proc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION, False, process.pid)
    if not h_proc:
        return False
    try:
        if not is_user_space_address(process.machine_id_address):
            return False
        
        current = read_memory(h_proc, process.machine_id_address, 49)
        if current == b"":
            return False
        
        data = new_machine_id.encode('utf-8') + b"\x00"
        if len(data) >= 50:
            return False
        
        if not write_memory(h_proc, process.machine_id_address, data):
            return False
        
        verify = read_memory(h_proc, process.machine_id_address, len(data))
        expected_bytes = new_machine_id.encode('utf-8')
        verify_clean = verify[:len(expected_bytes)]
        if verify_clean != expected_bytes:
            return False
        
        return True
    finally:
        CloseHandle(h_proc)


CONFIG_FILE_PATH = "machine_id.txt"


def save_config(last_machine_id: str) -> None:
    with open(CONFIG_FILE_PATH, 'w', encoding='utf-8') as f:
        f.write(last_machine_id)


def load_config():
    if not os.path.exists(CONFIG_FILE_PATH):
        return "", False
    try:
        with open(CONFIG_FILE_PATH, 'r', encoding='utf-8') as f:
            machine_id = f.read().strip()
            return (machine_id, bool(machine_id))
    except:
        return "", False


monitor_running = False
monitor_thread = None
modified_pids_lock = threading.Lock()
modified_pids = set()  # type: typing.Set[int]


def monitor_loop():
    global monitor_running
    while monitor_running:
        last_id, has_cfg = load_config()
        if not has_cfg:
            time.sleep(2)
            continue
        processes = get_qoder_processes()
        current_pids = {p.pid for p in processes}
        with modified_pids_lock:
            for pid in list(modified_pids):
                if pid not in current_pids:
                    modified_pids.remove(pid)
        for proc in processes:
            should_modify = False
            with modified_pids_lock:
                if proc.pid not in modified_pids:
                    modified_pids.add(proc.pid)
                    should_modify = True
            if should_modify:
                proc_copy = ProcessInfo(proc.pid, proc.name, proc.path, proc.base_address)
                if set_machine_id_address(proc_copy):
                    if modify_machine_id(proc_copy, last_id):
                        # Silent success - no need to spam console
                        pass
                    else:
                        with modified_pids_lock:
                            modified_pids.discard(proc_copy.pid)
                else:
                    with modified_pids_lock:
                        modified_pids.discard(proc_copy.pid)
        time.sleep(2)


def start_monitoring():
    global monitor_running, monitor_thread
    if not monitor_running:
        monitor_running = True
        monitor_thread = threading.Thread(target=monitor_loop, daemon=True)
        monitor_thread.start()


def stop_monitoring():
    global monitor_running, monitor_thread
    if monitor_running:
        monitor_running = False
        if monitor_thread and monitor_thread.is_alive():
            monitor_thread.join(timeout=5)


def display_menu():
    os.system('cls')
    print(f"{Colors.BRIGHT_BLUE}============================================={Colors.RESET}")
    print(f"{Colors.BRIGHT_GREEN}{Colors.BOLD}             QODER RESET TOOL               {Colors.RESET}")
    print(f"{Colors.BRIGHT_WHITE}Created by: {Colors.BRIGHT_BLUE}https://t.me/codetaik{Colors.RESET}")
    print(f"{Colors.BRIGHT_BLUE}============================================={Colors.RESET}")
    print(f"{Colors.BRIGHT_CYAN}1. Check status{Colors.RESET}")
    print(f"{Colors.BRIGHT_CYAN}2. Clear related files and registry{Colors.RESET}")
    print(f"{Colors.BRIGHT_CYAN}3. Machine ID management{Colors.RESET}")
    print(f"{Colors.BRIGHT_RED}0. Exit{Colors.RESET}")
    print(f"{Colors.BRIGHT_BLUE}============================================={Colors.RESET}")
    print(f"{Colors.BRIGHT_YELLOW}Select an option: {Colors.RESET}", end="")


def option1_check_status():
    print(f"{Colors.BRIGHT_GREEN}Checking Qoder status...{Colors.RESET}")
    processes = get_qoder_processes()
    if not processes:
        print(f"{Colors.BRIGHT_RED}No Qoder processes found.{Colors.RESET}")
        return
    
    print(f"{Colors.BRIGHT_GREEN}Found {len(processes)} Qoder process(es):{Colors.RESET}")
    print()
    
    for i, p in enumerate(processes, 1):
        print(f"{Colors.BRIGHT_BLUE}=== Process {i} ==={Colors.RESET}")
        print(f"{Colors.BRIGHT_WHITE}PID: {Colors.BRIGHT_YELLOW}{p.pid}{Colors.RESET}")
        print(f"{Colors.BRIGHT_WHITE}Name: {Colors.BRIGHT_YELLOW}{p.name}{Colors.RESET}")
        print(f"{Colors.BRIGHT_WHITE}Path: {Colors.BRIGHT_YELLOW}{p.path}{Colors.RESET}")
        print(f"{Colors.BRIGHT_WHITE}Base Address: {Colors.BRIGHT_YELLOW}0x{p.base_address:x}{Colors.RESET}")
        
        # Try to read machine ID
        proc = ProcessInfo(p.pid, p.name, p.path, p.base_address)
        if set_machine_id_address(proc):
            current_id = read_current_machine_id(proc)
            if current_id:
                print(f"{Colors.BRIGHT_WHITE}Current Machine ID: {Colors.BRIGHT_GREEN}{current_id}{Colors.RESET}")
            else:
                print(f"{Colors.BRIGHT_WHITE}Current Machine ID: {Colors.BRIGHT_RED}[Could not read]{Colors.RESET}")
        else:
            print(f"{Colors.BRIGHT_WHITE}Current Machine ID: {Colors.BRIGHT_RED}[Address resolution failed]{Colors.RESET}")
        print()
    
    # Show saved config
    last_id, has_cfg = load_config()
    if has_cfg:
        print(f"{Colors.BRIGHT_WHITE}Saved Machine ID in config: {Colors.BRIGHT_GREEN}{last_id}{Colors.RESET}")
    else:
        print(f"{Colors.BRIGHT_WHITE}No saved Machine ID in config{Colors.RESET}")


def safe_rmtree(path: str) -> bool:
    import shutil
    import stat
    try:
        if not os.path.exists(path):
            return True
        
        # Handle read-only files
        def handle_remove_readonly(func, path, exc):
            if os.path.exists(path):
                os.chmod(path, stat.S_IWRITE)
                func(path)
        
        shutil.rmtree(path, onerror=handle_remove_readonly)
        return True
    except Exception as e:
        # Try alternative method for stubborn directories
        try:
            import subprocess
            result = subprocess.run(['cmd', '/c', 'rmdir', '/s', '/q', path], 
                                  capture_output=True, text=True)
            return result.returncode == 0
        except Exception:
            return False


def delete_registry_tree(root, subkey: str) -> bool:
    try:
        import winreg
        def _delete_tree(hkey, sub):
            try:
                # First check if the key exists
                with winreg.OpenKey(hkey, sub, 0, winreg.KEY_READ) as key:
                    pass
            except OSError:
                # Key doesn't exist, consider it successful
                return True
            
            try:
                with winreg.OpenKey(hkey, sub, 0, winreg.KEY_ALL_ACCESS) as key:
                    # Delete all subkeys first
                    while True:
                        try:
                            child = winreg.EnumKey(key, 0)
                            _delete_tree(hkey, sub + "\\" + child)
                        except OSError:
                            break
                # Delete the key itself
                winreg.DeleteKey(hkey, sub)
                return True
            except OSError as e:
                # If deletion fails, try using reg.exe command
                try:
                    import subprocess
                    cmd = ['reg', 'delete', f'HKCU\\{subkey}', '/f']
                    result = subprocess.run(cmd, capture_output=True, text=True)
                    return result.returncode == 0
                except Exception:
                    return False
        return _delete_tree(root, subkey)
    except Exception:
        return False


def option2_clear_data():
    print("This will delete all Qoder related files and registry entries.")
    choice = input("Are you sure you want to continue? (y/n): ").strip().lower()
    if choice != 'y':
        print("Operation cancelled.")
        return
    appdata = os.environ.get('APPDATA', '')
    local_appdata = os.environ.get('LOCALAPPDATA', '')
    userprofile = os.environ.get('USERPROFILE', '')
    qoder_appdata = os.path.join(appdata, 'Qoder') if appdata else ''
    qoder_local = os.path.join(local_appdata, 'Qoder') if local_appdata else ''
    qoder_profile = os.path.join(userprofile, '.qoder') if userprofile else ''

    success = True
    if qoder_appdata and os.path.exists(qoder_appdata):
        if safe_rmtree(qoder_appdata):
            print(f"Deleted directory: {qoder_appdata}")
        else:
            print(f"Failed to delete directory: {qoder_appdata}")
            success = False
    if qoder_local and os.path.exists(qoder_local):
        if safe_rmtree(qoder_local):
            print(f"Deleted directory: {qoder_local}")
        else:
            print(f"Failed to delete directory: {qoder_local}")
            success = False
    if qoder_profile and os.path.exists(qoder_profile):
        if safe_rmtree(qoder_profile):
            print(f"Deleted directory: {qoder_profile}")
        else:
            print(f"Failed to delete directory: {qoder_profile}")
            success = False

    try:
        import winreg
        if delete_registry_tree(winreg.HKEY_CURRENT_USER, r"Software\Qoder"):
            print("Deleted registry key: HKEY_CURRENT_USER\\Software\\Qoder")
        else:
            print("Registry key not found or already deleted: HKEY_CURRENT_USER\\Software\\Qoder")
            # Don't mark as failure if key doesn't exist
    except Exception:
        print("Failed to access registry key: HKEY_CURRENT_USER\\Software\\Qoder")
        success = False

    if success:
        print("All Qoder related files and registry entries have been successfully removed.")
    else:
        print("Some operations failed. Please check the error messages above.")


def read_current_machine_id(process: ProcessInfo) -> str:
    """Read current machine ID from process memory"""
    h_proc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, process.pid)
    if not h_proc:
        return ""
    try:
        if not is_user_space_address(process.machine_id_address):
            return ""
        current_data = read_memory(h_proc, process.machine_id_address, 49)
        if current_data:
            # Find the null terminator to get exact string length
            null_pos = current_data.find(b'\x00')
            if null_pos != -1:
                clean_data = current_data[:null_pos]
            else:
                clean_data = current_data.rstrip(b"\x00")
            
            result = clean_data.decode('utf-8', errors='ignore')
            return result
        return ""
    finally:
        CloseHandle(h_proc)


def display_machine_id_menu():
    os.system('cls')
    print(f"{Colors.BRIGHT_BLUE}============================================={Colors.RESET}")
    print(f"{Colors.BRIGHT_GREEN}{Colors.BOLD}           MACHINE ID MANAGEMENT           {Colors.RESET}")
    print(f"{Colors.BRIGHT_WHITE}Created by: {Colors.BRIGHT_BLUE}https://t.me/codetaik{Colors.RESET}")
    print(f"{Colors.BRIGHT_BLUE}============================================={Colors.RESET}")
    
    last_id, has_cfg = load_config()
    if has_cfg:
        print(f"{Colors.BRIGHT_WHITE}Current saved machine ID: {Colors.BRIGHT_GREEN}{last_id}{Colors.RESET}")
    else:
        print(f"{Colors.BRIGHT_YELLOW}No saved machine ID found.{Colors.RESET}")
    
    print(f"{Colors.BRIGHT_BLUE}============================================={Colors.RESET}")
    print(f"{Colors.BRIGHT_CYAN}1. Use existing machine ID{Colors.RESET}")
    print(f"{Colors.BRIGHT_CYAN}2. Generate new machine ID{Colors.RESET}")
    print(f"{Colors.BRIGHT_RED}0. Back to main menu{Colors.RESET}")
    print(f"{Colors.BRIGHT_BLUE}============================================={Colors.RESET}")
    print(f"{Colors.BRIGHT_YELLOW}Select an option: {Colors.RESET}", end="")

def option3_machine_id_management():
    while True:
        display_machine_id_menu()
        try:
            choice = int(input().strip())
        except ValueError:
            print(f"{Colors.BRIGHT_RED}Invalid input.{Colors.RESET}")
            input("\nPress Enter to continue...")
            continue
    
        if choice == 0:
            return
        elif choice == 1:
            last_id, has_cfg = load_config()
            if not has_cfg:
                print(f"\n{Colors.BRIGHT_RED}No saved machine ID found. Please generate one first.{Colors.RESET}")
                input("\nPress Enter to continue...")
                continue
            machine_id_to_use = last_id
            print(f"\n{Colors.BRIGHT_GREEN}Using existing machine ID: {Colors.BRIGHT_YELLOW}{machine_id_to_use}{Colors.RESET}")
        elif choice == 2:
            machine_id_to_use = str(uuid.uuid4())
            print(f"\n{Colors.BRIGHT_GREEN}Generated new machine ID: {Colors.BRIGHT_YELLOW}{machine_id_to_use}{Colors.RESET}")
            save_config(machine_id_to_use)
            print(f"{Colors.BRIGHT_GREEN}Configuration updated with new machine ID.{Colors.RESET}")
        else:
            print(f"{Colors.BRIGHT_RED}Invalid option.{Colors.RESET}")
            input("\nPress Enter to continue...")
            continue

        # Apply to running processes
        apply_choice = input("\nWould you like to apply this machine ID to running processes? (y/n): ").strip().lower()
        if apply_choice == 'y':
            print(f"\n{Colors.BRIGHT_GREEN}Applying machine ID: {Colors.BRIGHT_YELLOW}{machine_id_to_use}{Colors.RESET}")
            
            processes = get_qoder_processes()
            if not processes:
                print(f"{Colors.BRIGHT_RED}No processes found.{Colors.RESET}")
            else:
                success_count = 0
                for p in processes:
                    proc = ProcessInfo(p.pid, p.name, p.path, p.base_address)
                    
                    if not set_machine_id_address(proc):
                        continue
                    
                    # Read current machine ID
                    current_id = read_current_machine_id(proc)
                    if not current_id:
                        continue
                    
                    # Only modify if different
                    if current_id != machine_id_to_use:
                        if modify_machine_id(proc, machine_id_to_use):
                            print(f"{Colors.BRIGHT_GREEN}Machine ID changed from {Colors.BRIGHT_YELLOW}{current_id}{Colors.BRIGHT_GREEN} to {Colors.BRIGHT_YELLOW}{machine_id_to_use}{Colors.RESET}")
                            success_count += 1
                    else:
                        print(f"{Colors.BRIGHT_BLUE}Machine ID already set to {Colors.BRIGHT_YELLOW}{machine_id_to_use}{Colors.RESET}")
                        success_count += 1
                
                print(f"{Colors.BRIGHT_GREEN}✓ Successfully updated {success_count}/{len(processes)} processes{Colors.RESET}")
        
        # Ask about monitoring
        print(f"\n{Colors.BRIGHT_BLUE}============================================={Colors.RESET}")
        monitor_choice = input(f"{Colors.BRIGHT_YELLOW}Enable auto-monitoring for future processes? (y/n): {Colors.RESET}").strip().lower()
        
        global monitor_running
        if monitor_choice == 'y':
            if not monitor_running:
                start_monitoring()
                print(f"{Colors.BRIGHT_GREEN}✓ Auto-monitoring enabled{Colors.RESET}")
            else:
                print(f"{Colors.BRIGHT_YELLOW}✓ Auto-monitoring already active{Colors.RESET}")
        else:
            if monitor_running:
                stop_monitoring()
                print(f"{Colors.BRIGHT_YELLOW}✗ Auto-monitoring disabled{Colors.RESET}")
            else:
                print(f"{Colors.BRIGHT_WHITE}✗ Auto-monitoring remains off{Colors.RESET}")
        
        # Important note
        if monitor_choice != 'y':
            print(f"\n{Colors.BRIGHT_YELLOW}⚠️  Remember: Run this tool every time you start the app{Colors.RESET}")
        
        input("\nPress Enter to continue...")


# Removed option4 - monitoring is now integrated into option3


def main():
    while True:
        display_menu()
        try:
            option = int(input().strip())
        except Exception:
            option = -1
        if option == 1:
            option1_check_status()
        elif option == 2:
            option2_clear_data()
        elif option == 3:
            option3_machine_id_management()
        elif option == 0:
            print(f"{Colors.BRIGHT_GREEN}Exiting...{Colors.RESET}")
            break
        else:
            print(f"{Colors.BRIGHT_RED}Invalid option selected.{Colors.RESET}")
        input("\nPress Enter to continue...")
    stop_monitoring()


if __name__ == '__main__':
    main()



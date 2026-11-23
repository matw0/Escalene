from escalene.models import Process
from win32 import win32process, win32api, win32security
import win32con
import pywintypes
import os
from escalene.collectors.windows_token import Get_Token_Information_TU, Look_Up_Account_SID

def collect_processes() -> tuple[Process, ...]:
    PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
    processes = []

    PIDs = win32process.EnumProcesses()
    for PID in PIDs:
        executable_path = None
        process_name = None
        collection_errors = ()
        run_as_account = None

        try:
            process_handle = win32api.OpenProcess(
                PROCESS_QUERY_LIMITED_INFORMATION, False, PID
            )
        except pywintypes.error as error:
            collection_errors += (f"OpenProcess: {error.winerror}: {error.strerror}",)
        else:
            try:
                try:
                    executable_path = win32process.GetModuleFileNameEx(process_handle, 0)
                    process_name = os.path.basename(executable_path)
                except pywintypes.error as error:
                    collection_errors += (f"GetModuleFileNameEx: {error.winerror}: {error.strerror}",)

                try:
                    token_handle = win32security.OpenProcessToken(process_handle, win32con.TOKEN_QUERY)
                    try:
                        user_sid = Get_Token_Information_TU(token_handle)[0]
                        name, domain, _ = Look_Up_Account_SID(user_sid)
                        run_as_account = f"{domain}\\{name}" if domain else name
                    finally:
                        win32api.CloseHandle(token_handle)
                except pywintypes.error as error:
                    collection_errors += (f"Run as account lookup: {error.winerror} | {error.strerror}",)
            finally:
                win32api.CloseHandle(process_handle)
        
        processes.append(Process(PID=PID, name=process_name,exec_path=executable_path, collection_errors=collection_errors, run_as_account=run_as_account))

    return tuple(processes)
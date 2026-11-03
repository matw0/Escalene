from win32 import win32service
from escalene.models import ServiceRecord
import pywintypes
import winerror


def service_state_name(state: int) -> str:
    states = {
        win32service.SERVICE_STOPPED: "stopped",
        win32service.SERVICE_START_PENDING: "start pending",
        win32service.SERVICE_STOP_PENDING: "stop pending",
        win32service.SERVICE_RUNNING: "running",
        win32service.SERVICE_CONTINUE_PENDING: "continue pending",
        win32service.SERVICE_PAUSE_PENDING: "pause pending",
        win32service.SERVICE_PAUSED: "paused",
    }

    return states.get(state, f"unknown ({state})")

def service_start_type_name(start_type: int) -> str:
    start_types = {
        win32service.SERVICE_BOOT_START: "boot",
        win32service.SERVICE_SYSTEM_START: "system",
        win32service.SERVICE_AUTO_START: "automatic",
        win32service.SERVICE_DEMAND_START: "manual",
        win32service.SERVICE_DISABLED: "disabled",
    }

    return start_types.get(start_type, f"unknown ({start_type})")

def can_change_service_config(service_manager, service_name: str) -> tuple[bool | None, str | None]:
    service_handle = None
    try:
        service_handle = win32service.OpenService(service_manager, service_name, win32service.SERVICE_CHANGE_CONFIG)
        return True, None
    except pywintypes.error as error:
        if error.winerror == winerror.ERROR_ACCESS_DENIED:
            return False, None
        
        error_message = (
            f"Could not determine SERVICE_CHANGE_CONFIG access for "
            f"{service_name}: {error.winerror} - {error.strerror}")
            
        return None, error_message

    finally:
        if service_handle is not None:
            win32service.CloseServiceHandle(service_handle)


def collect_services() -> tuple[ServiceRecord, ...]:
    manager_access = (win32service.SC_MANAGER_CONNECT | win32service.SC_MANAGER_ENUMERATE_SERVICE)
    service_manager = win32service.OpenSCManager(None, None, manager_access,)

    try:
        services = win32service.EnumServicesStatus(service_manager, win32service.SERVICE_WIN32, win32service.SERVICE_STATE_ALL)
    
        records = []

        for service_name, display_name, status in services:
            current_state = status[1]

            service_handle = None
            binary_path = None
            start_type = None
            run_as_account = None
            collection_errors = ()

            try:
                service_handle = win32service.OpenService(service_manager,service_name,win32service.SERVICE_QUERY_CONFIG,)
                configuration = win32service.QueryServiceConfig(service_handle)

                start_type = service_start_type_name(configuration[1])
                binary_path = configuration[3]
                run_as_account = configuration[7]

            except pywintypes.error as error:
                collection_errors += (f"{error.winerror}: {error.strerror}",)

            finally:
                if service_handle is not None:
                    win32service.CloseServiceHandle(service_handle)

            can_change_config, permission_error = can_change_service_config(service_manager, service_name,)
            if permission_error is not None:
                collection_errors += (permission_error,)


            records.append(ServiceRecord(name=service_name, display_name=display_name, binary_path=binary_path, start_type=start_type, run_as_account=run_as_account, state=service_state_name(current_state), collection_errors=collection_errors,
                                         can_change_config=can_change_config,))
        return tuple(records)

    finally:
        win32service.CloseServiceHandle(service_manager)



from win32 import win32api, win32security
import win32con
from escalene.models import Token

def Open_Process_Token(func):
    def wrapper():
        return win32security.OpenProcessToken(func(), win32con.TOKEN_QUERY)
    return wrapper

@Open_Process_Token
def Get_Current_Process():
    return win32api.GetCurrentProcess()

def Get_Token_Information_TU(token_handle):
    return win32security.GetTokenInformation(token_handle, win32security.TokenUser)

def Get_Token_Information_IE(token_handle):
    return bool(win32security.GetTokenInformation(token_handle, win32security.TokenElevation))

def Get_Token_Information_IL(token_handle):
        IL_SID = (win32security.GetTokenInformation(token_handle, win32security.TokenIntegrityLevel))[0]
        count = IL_SID.GetSubAuthorityCount()
        RID = IL_SID.GetSubAuthority(count - 1)
        
        if RID == 0x0000: return "Untrusted"
        elif RID == 0x1000: return "Low"
        elif RID == 0x2000: return "Medium"
        elif RID == 0x2100: return "Medium Plus"
        elif RID == 0x3000: return "High"
        elif RID == 0x4000: return "System"
        elif RID == 0x5000: return "Protected Process"
        return f"Unknown ({hex(RID)})"

def Check_Local_Admin():
    ADMIN_SID = win32security.CreateWellKnownSid(win32security.WinBuiltinAdministratorsSid)
    return bool(win32security.CheckTokenMembership(None, ADMIN_SID))


def Look_Up_Account_SID(SID):
    return win32security.LookupAccountSid(None, SID)

def Convert_SID_String_SID(user_SID):
    return win32security.ConvertSidToStringSid(user_SID)


def collect_token_context():
    account_name = "Unknown"
    user_SID_UP = None
    is_elevated = None
    integrity_level = None
    is_local_admin = False
    token_h = None
    
    try:
        token_h = Get_Current_Process()
        user_SID_UP = Get_Token_Information_TU(token_h)
        user_SID_P = user_SID_UP[0]
        SID_string = Convert_SID_String_SID(user_SID_P)
        account_name, domain, _ = Look_Up_Account_SID(user_SID_P)
        account_name = (f"{domain}\\{account_name}" if domain else account_name)

        is_elevated = Get_Token_Information_IE(token_h)
        integrity_level = Get_Token_Information_IL(token_h)


        return Token(account_name=account_name, user_SID=SID_string, is_elevated=is_elevated, integrity_level=integrity_level, is_local_admin=Check_Local_Admin())
    
    finally:
        if token_h is not None:
            win32api.CloseHandle(token_h)
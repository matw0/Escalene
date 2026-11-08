from escalene.collectors.windows_services import collect_services
from escalene.collectors.windows_token import collect_token_context

def main() -> None:
    services = collect_services()
    token = collect_token_context()

    print("Current token")
    print(f"Account:       {token.account_name}")
    print(f"SID:           {token.user_SID or 'unavailable'}")
    print(f"Elevated:      {token.is_elevated}")
    print(f"Integrity:     {token.integrity_level or 'unavailable'}")
    print(f"Local admin:   {token.is_local_admin}")
    print(f"Errors:        {', '.join(token.collection_errors) or 'none'}")
    print()

    print(f"Captured {len(services)} windows services.\n")

    for service in services:
        print(f"\nName:         {service.name}")
        print(f"Display name: {service.display_name}")
        print(f"State:        {service.state or 'unavailable'}")
        print(f"Start type:   {service.start_type or 'unavailable'}")
        print(f"Account:      {service.run_as_account or 'unavailable'}")
        print(f"Binary path:  {service.binary_path or 'unavailable'}")
        print(
            "Errors:       "
            + (", ".join(service.collection_errors) or "none")
        )
        print(f"Change Config: {service.can_change_config}")


if __name__ == "__main__":
    print(r"""
 ______   ______   ______   ________   __       ______   ___   __    ______      
/_____/\ /_____/\ /_____/\ /_______/\ /_/\     /_____/\ /__/\ /__/\ /_____/\     
\::::_\/_\::::_\/_\:::__\/ \::: _  \ \\:\ \    \::::_\/_\::\_\\  \ \\::::_\/_    
 \:\/___/\\:\/___/\\:\ \  __\::(_)  \ \\:\ \    \:\/___/\\:. `-\  \ \\:\/___/\   
  \::___\/_\_::._\:\\:\ \/_/\\:: __  \ \\:\ \____\::___\/_\:. _    \ \\::___\/_  
   \:\____/\ /____\:\\:\_\ \ \\:.\ \  \ \\:\/___/\\:\____/\\. \`-\  \ \\:\____/\ 
    \_____\/ \_____\/ \_____\/ \__\/\__\/ \_____\/ \_____\/ \__\/ \__\/ \_____\/ 


                                    by matw0
                        github - https://github.com/matw0
    """)
    #main()

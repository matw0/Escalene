from escalene.collectors.windows_services import collect_services
from escalene.collectors.windows_token import collect_token_context
from escalene.analyzers.windows_services import analyze_services
from escalene.collectors.windows_processes import collect_processes
from escalene.models import ScanResult
import sys
import threading
from contextlib import contextmanager
from itertools import cycle
import argparse


BANNER = r"""
 ______   ______   ______   ________   __       ______   ___   __    ______      
/_____/\ /_____/\ /_____/\ /_______/\ /_/\     /_____/\ /__/\ /__/\ /_____/\     
\::::_\/_\::::_\/_\:::__\/ \::: _  \ \\:\ \    \::::_\/_\::\_\\  \ \\::::_\/_    
 \:\/___/\\:\/___/\\:\ \  __\::(_)  \ \\:\ \    \:\/___/\\:. `-\  \ \\:\/___/\   
  \::___\/_\_::._\:\\:\ \/_/\\:: __  \ \\:\ \____\::___\/_\:. _    \ \\::___\/_  
   \:\____/\ /____\:\\:\_\ \ \\:.\ \  \ \\:\/___/\\:\____/\\. \`-\  \ \\:\____/\ 
    \_____\/ \_____\/ \_____\/ \__\/\__\/ \_____\/ \_____\/ \__\/ \__\/ \_____\/ 


                                                 ________
                                                |\       \
                                                |  \       \ 
                                         _______|    \       \ 
                                        |\      \     +-------+
                                        |  \      \   |       |
                                 _______|    \      \ |       |
                                 |\      \     +-----+        |
                                 |  \      \   |              |
                          _______|    \      \ |              |
                          |\      \     +-----+               |
                          |  \      \   |                     |
                          |    \      \ |                     |
                           \     +-----+                      |
                             \   |  https://github.com/matw0  |
                               \ |        by matw0            |
                                +-----------------------------+
    
"""
def animate_loading(message: str, stop_event: threading.Event) -> None:
    for frame in cycle("|/-\\"):
        if stop_event.is_set():
            break

        sys.stderr.write(f"\r[{frame}] {message}")
        sys.stderr.flush()
        stop_event.wait(0.1)

@contextmanager
def spinner(message: str):
    stop_event = threading.Event()

    spinner_thread = threading.Thread(
        target=animate_loading,
        args=(message, stop_event),
        daemon=True,
    )

    spinner_thread.start()

    try:
        yield
    except Exception:
        stop_event.set()
        spinner_thread.join()
        sys.stderr.write(f"\r[!] {message} failed.\n")
        sys.stderr.flush()
        raise
    else:
        stop_event.set()
        spinner_thread.join()
        sys.stderr.write(f"\r[*] {message} complete.\n")
        sys.stderr.flush()


def main(args: argparse.Namespace) -> None:
    print(BANNER)

    run_services = args.target in ("all", "services")
    show_token = args.target in ("all", "token")
    services = ()

    if args.target == "services":
        message = "Collecting data for the service audit"
    elif args.target == "token":
        message = "Collecting token information"
    elif args.target == "processes":
        message = "Collecting current processes information"
    else:
        message = "Processing audit for token, service and process enumeration"

    with spinner(message):
        if args.target == "processes":
            processes = collect_processes()
        else:
            token = collect_token_context()

            if run_services:
                services = collect_services()

    if args.target == "processes":
        print(f"\nProcesses collected: {len(processes)}")
        if args.verbose:
            for process in processes:
                PID = process.PID
                name = process.name or "Unavailable"
                path = process.exec_path or "Unavailable"
                run_as_account = process.run_as_account or "Unavailable"
                print(f"{PID:>7}  {name:<28}  {run_as_account:<32}  {path}")
        else:
            return None

    if show_token:
        print(f"\nAccount: {token.account_name}")
        print(f"Elevated: {token.is_elevated}")
        print(f"Integrity: {token.integrity_level}")
        print(f"Collection errors: {len(token.collection_errors)}\n")

        if args.verbose and not run_services:
            for error in token.collection_errors:
                print(f"  [Token] {error}")


    if not run_services:
        return None

    findings = analyze_services(services, token) 
    scan = ScanResult(token=token, services=services, findings=findings)

    token_error_count = len(token.collection_errors)
    service_error_count = sum(len(service.collection_errors) for service in scan.services)
    collection_error_count = token_error_count + service_error_count

    print("\nScan summary")
    print(f"Services collected: {len(scan.services)}")
    print(f"Findings:           {len(scan.findings)}")
    print(f"Collection errors:  {collection_error_count}")

    if args.verbose and collection_error_count:
        print("\nCollection error details")

        for error in token.collection_errors:
            print(f"  [Token] {error}")

        for service in scan.services:
            for error in service.collection_errors:
                print(f"[!]--------[Service: {service.name}] {error}")

    if not scan.findings:
        print("\nNo findings from the checks completed.")

    for finding in scan.findings:
        print(f"\nID:       {finding.finding_id}")
        print(f"Title:    {finding.title}")
        print(f"Target:   {finding.target}")
        print(f"Severity: {finding.severity}")
        print(f"Description: {finding.description}")
        print("Evidence:")
        for evidence_item in finding.evidence:
            print(f"  - {evidence_item}")
        print(f"Remediation: {finding.remediation}")
        if finding.limitations:
            print("Limitations:")
            for limitation in finding.limitations:
                print(f"  - {limitation}")   


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="""Escalene is a read-only Windows security auditing tool. It inventories local services, reports the current user’s access context, and highlights permission findings for review.""", add_help=False,)
    parser.add_argument(
        "-?", "-h", "-H", "--help",
        action="help",
        help="Show help dropdown menus",
    )
    parser.add_argument(
    "-V",
    "--verbose",
    action="store_true",
    help="Show detailed collection errors",
)
    parser.add_argument(
        "-T",
        "--target",
        choices=("all", "services", "token", "processes"),
        default="all",
        help="Choose which local checks to run - (default:all)",
    )
    # parser.add_argument(
    #     "--script",
    #     choices=("all", "services", "token", "processes"),
    #     default="all",
    #     help="Choose which local checks to run - (default:all)",
    # )

    if len(sys.argv) == 1:
        parser.print_help()
        raise SystemExit(0)
    
    args = parser.parse_args()
    main(args)

    

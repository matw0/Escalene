from escalene.collectors.windows_services import collect_services
from escalene.collectors.windows_token import collect_token_context
from escalene.analyzers.windows_services import analyze_services
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


def main() -> None:
    print(BANNER)

    with spinner("Collecting token and service information..."):
        token = collect_token_context()
        services = collect_services()

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
        print("Evidence:")

        for evidence_item in finding.evidence:
            print(f"  - {evidence_item}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="""Escalene is a read-only Windows security auditing tool. It inventories local services, reports the current user’s access context, and highlights permission findings for review.""")
    parser.add_argument(
    "-v",
    "--verbose",
    action="store_true",
    help="Show detailed collection errors.",
)
    args = parser.parse_args()
    main()

    

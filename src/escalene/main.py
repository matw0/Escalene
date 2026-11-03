from escalene.collectors.windows_services import collect_services

def main() -> None:
    services = collect_services()
    print(f"Captured {len(services)} windows services.\n")

    for service in services[:10]:
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
    main()
## Current status

Escalene currently performs read-only local Windows service enumeration. It
collects service state, startup type, execution account and binary command line.
It also checks whether the current effective token can obtain
`SERVICE_CHANGE_CONFIG` access.

The project does not currently exploit findings or modify service
configurations. Permission results still require analysis alongside the current token context and service execution account.
Eventually the tool will be dependent on user input, including flags, helping to filter for misconfigurations and potential privilege escalation.

Once service collection and analyis is complete and reliable, processes enumeration will be implemented next.
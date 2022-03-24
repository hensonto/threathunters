# Symantec Threat Hunters

# Henson Notes:
Assumption:
https://techdocs.broadcom.com/us/en/symantec-security-software/endpoint-security-and-management/endpoint-detection-and-response/4-6/search-fields-and-descriptions-v126755396-d38e59231/event-summary-type-ids-v121987556-d38e58861.html
type_ids
Event type and ID number
	
Description
1: Application Activity
	
Reports status information about an application activity an end user performed. For example, an administrator runs a database search or endpoint search. Or the administrator runs a command line interface command (e.g., expand_storage).
20: User Session Audit
	
Reports user logon and logoff activity at a management console or a managed client.
21: Entity Audit
	
Reports activity by a managed client, a micro service, or a user at a management console. The activity can be a create, update, and delete operation on a managed entity. For example, the Policy service records policy change events, the SEP client reports local policy changes, and the policy administrator updates policies at the console.
238: Device Control
	
Reports a device control disabled device.
239: Device Control
	
Reports a buffer overflow event.
240: Device Control
	
Reports software protection has thrown an exception.
502: Application Control
	
Reports agent behavior events.
1000: System Health
	
Reports any change to a component's health which impacts overall health of the Symantec EDR
appliance, software, or hardware. For example "DB Connection failure/success ", "Low Disk", or "High CPU".
4096: Reputation Lookup
	
Reports when a request is made to Symantec Insight or Symantec Mobile Insight for information about the reputation of a file.
4098: Intrusion Prevention
	
Reports when a Symantec intrusion prevention system detected a possible malicious IPS signature.
4099: Suspicious File Detection
	
Reports when a suspicious file was detected.
4100: SONAR Detection
	
Reports when Symantec Online Network for Advanced Response (SONAR) technology detected a new threat.
SEDR shows no 4100 or 4102 events
4102: Antivirus Detection (Endpoint)
	
Reports when an antivirus was detected on an endpoint.
Many 4102 events are recorded
SEDR shows no 4100 or 4102 events
4109: Dynamic Adversary Intelligence from Endpoint
	
Adversary intelligence from the endpoint control point.
4110: Dynamic Adversary Intelligence from Network
	
Adversary intelligence from the network control point.
4112: Deny List (IP/URL/Domain)
	
Reports when an IP, URL, or Domain was detected that is in a Symantec-provided deny list or the Symantec EDR
deny list.
4113: Vantage Detection
	
Reports when Symantec Vantage technology detected malicious activity on an endpoint or Vantage signature-based threats were found in the network system.
4115: Insight Detection
	
Reports when Symantec Endpoint Protection has queried the file reputation server about a file on a managed endpoint or Insight detected malicious activity that occurred in your network.
4116: Mobile Insight Detection
	
Reports when Symantec Mobile Insight technology detected issues with an Android executable.
4117: Sandboxing Detection
	
Reports when sandboxing technology observed a malicious file in your network.
4118: Deny List (file)
	
Reports when a file was detected that is in a Symantec-provided deny list or the Symantec EDR
deny list.
4123: Endpoint Detection (file)
	
Reports when a suspicious file was detected on an endpoint.  As of Symantec EDR 4.5 and later and SEPM 14.3 RU1 and later, this event also includes SHA256 hash blocking events.
4124: Endpoint Detection (IP/URL/Domain)
	
Reports when a suspicious IP, URL, or domain was detected on an endpoint. Also reports Application Control and Device Control events.
4125: Email Detection
	
Reports when suspicious email was detected.
4353: Antivirus Detection  (Network)
	
Reports when an antivirus was detected on a network.
8000: Session Event
	
Reports when a user attempts a log on or log off, successfully or otherwise.
8001: Process Event
	
Reports when a process launches, terminates, or opens another process, successful or otherwise.
8002: Module Event
	
Reports when a process loads or unloads a module.
8003: File Event
	
Reports operations on file system objects.
8004: Directory Event
	
Reports operations on directories.
8005: Registry Key Event
	
Reports actions on Windows registry keys.
8006: Registry Value Event
	
Reports actions on Windows registry values.
8007: Network Event
	
Reports attempted network connections, successful or otherwise.
8009: Kernel Event
	
Reports when an actor process creates, reads, or deletes a kernel object.
8015:  ETW (Event Tracing for Windows) Event
	
Reports ETW activity. 
8016:  Startup Application Configuration Change
	
Reports when a startup application configuration has been created, deleted or modified.
8018:  AMSI (AntiMalware Scan Interface) Event
	
Reports AMSI activity.
8080: Session Query Result
	
Reports information on existing user sessions.
8081: Process Query Result
	
Reports information on a running process.
8082: Module Query Result
	
Reports information on loaded modules.
8083: File Query Result
	
Reports information on file system objects.
8084: Directory Query Result
	
Reports directory information.
8085: Registry Key Query Result
	
Reports information on Windows Registry keys.
8086: Registry Value Query Result
	
Reports information on Windows Registry values.
8089: Kernel Object Query Result
	
Reports information on kernel objects.
8090: Service Query Result
	
Reports information service queries.
8099: Query Command Errors
	
Reports information on EOC (Evidence of Compromise Query command errors.
8103: File Remediation
	
Reports information on file system objects.
8119: File Remediation Errors
	
Reports information on errors that result from an EOC (Evidence of Compromise) file remediation action.

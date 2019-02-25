###################### Winlogbeat Configuration Example ##########################

# This file is an example configuration file highlighting only the most common
# options. The winlogbeat.full.yml file from the same directory contains all the
# supported options with more comments. You can use it as a reference.
#
# You can find the full configuration reference here:
# https://www.elastic.co/guide/en/beats/winlogbeat/index.html

#======================= Winlogbeat specific options ==========================

# event_logs specifies a list of event logs to monitor as well as any
# accompanying options. The YAML data type of event_logs is a list of
# dictionaries.
#
# The supported keys are name (required), tags, fields, fields_under_root,
# forwarded, ignore_older, level, event_id, provider, and include_xml. Please
# visit the documentation for the complete details of each option.
# https://go.es.io/WinlogbeatConfig
#winlogbeat.event_logs:
#  - name: Application
#    ignore_older: 72h
#  - name: Security
#  - name: System
  
winlogbeat.event_logs:
  - name: ForwardedEvents

processors:
  - drop_event.when.or:
    - equals.event_id: 5156 # Filter out Windows Firewall has allowed a connection
    - equals.event_id: 5145 # Filter out network share object access check
    - equals.event_id: 16 # Filter out counter could not be modified
    - equals.event_id: 4656 
    - equals.event_id: 36887 # A handle to an object was requested
    - equals.event_id: 4658 # The handle to an object was closed
    - equals.event_id: 5663 # An attempt was made to access an object
    - equals.event_id: 5158 # Filter out Windows Firewall has allowed local bind
    - equals.event_id: 5154 # Filter out Windows Firewall has allowed a port
    - equals.event_id: 4985 # Filter out Windows state of a transaction has changed
    - equals.event_id: 560 # Filter out Object Access
    - equals.event_id: 562 # Filter out Handle Closed
    - equals.event_id: 578 # Filter out Privilege object operation
    - equals.event_id: 861 # Filter out Windows Firewall has detected an application listening for incoming traffic
    - equals.event_id: 567 # Filter out Object accesss attempt
    - equals.event_id: 8 # Filter out Create Remote Thread
    - equals.event_id: 5140 # Filter out a network object was accessed
    - equals.event_id: 600 # Filter out a process was assigned a primary token
    - equals.event_id: 5158 #Filter out new listening ports events
    - contains.event_data: "255.255.255.255" #Drop broadcast traffic
    - contains.event_data: "224.0.0" #Drop multicast traffic
    - contains.event_data: "239.255.255.250" #Drop multicast traffic
    - contains.event_data: "SeSystemtimePrivilege" # Drop Time Privilege events
    - contains.event_data: "SeBackupPrivilege" # Drop SeBackupPrivilege until users are not admins
    - contains.event_data: "SeCreateGlobalPrivilege" #Drop SeCreateGlobalPrivilege use
    - contains.event_data: "CoreNet-Teredo-In" # Drop CoreNet-Teredo-In rule failures as it is going to happen
    - contains.event_data: "CoreNet-IPHTTPS-In" # Drop CoreNet-IPHTTPS-In rule failures as it is going to happen
    - contains.event_data: "ntp" # Drop ntp related application logs
    - contains.event_data: "PrintIsolationHost" # Drop Sysmon PrintIsolationHost related application logs
    - contains.event_data: "esif_assist" #  Drop intel NIC sysmon events
  - drop_event.when.and:
    - equals.event_id: 5158 
    - contains.event_data: "chrome" #Drop chrome logs
  - drop_event.when.and:
    - equals.event_id: 5154 
    - contains.event_data: "System" #Drop System listening port logs
  - drop_event.when.and:
    - equals.event_id: 5154 
    - contains.event_data: "lsass" #Drop lsass listening port logs	
  - drop_event.when.and:
    - equals.event_id: 5154 
    - contains.event_data: "winit" #Drop system listening port logs
  - drop_event.when.and:
    - equals.event_id: 5154 
    - contains.event_data: "services" #Drop system listening port logs
  - drop_event.when.and:
    - equals.event_id: 5154 
    - contains.event_data: "teamviewer" #Drop system listening port logs
  - drop_event.when.and:
    - equals.event_id: 5154 
    - contains.event_data: "mdnsresponder" #Drop system listening port logs
  - drop_event.when.and:
    - equals.event_id: 3 
    - contains.event_data: "F5" #Drop network connection logs
  - drop_event.when.and:
    - equals.event_id: 3 
    - contains.event_data: "dfsrs" #Drop network connection logs
  - drop_event.when.and:
    - equals.event_id: 3 
    - contains.event_data: "apache" #Drop network connection logs
  - drop_event.when.and:
    - equals.event_id: 3 
    - contains.event_data: "mDNSResponder" #Drop network connection logs
  - drop_event.when.and:
    - equals.event_id: 3 
    - contains.event_data: "Lync" #Drop network connection logs
  - drop_event.when.and:
    - equals.event_id: 3 
    - contains.event_data: "w3wp" #Drop network connection logs
  - drop_event.when.and:
    - equals.event_id: 3 
    - contains.event_data: "TeamViewer" #Drop network connection logs
  - drop_event.when.and:
    - equals.event_id: 3 
    - contains.event_data: "taskhost" #Drop network connection logs
  - drop_event.when.and:
    - equals.event_id: 3 
    - contains.event_data: "SQL" #Drop network connection logs
  - drop_event.when.and:
    - equals.event_id: 3 
    - contains.event_data: "EMET" #Drop network connection logs
  - drop_event.when.and:
    - equals.event_id: 3 
    - contains.event_data: "Skype" #Drop network connection logs
  - drop_event.when.and:
    - equals.event_id: 3 
    - contains.event_data: "Exchange" #Drop network connection logs
  - drop_event.when.and:
    - equals.event_id: 3 
    - contains.event_data: "dfssvc" #Drop network connection logs
  - drop_event.when.and:
    - equals.event_id: 4624
    - contains.event_data.TargetUserName: "appbatch" # Drop Service Account Logons
  - drop_event.when.and:
    - equals.event_id: 4624
    - contains.event_data.TargetUserName: "VmwareView" # Drop Service Account Logons
  - drop_event.when.and:
    - equals.event_id: 4624
    - contains.event_data.TargetUserName: "RemoteControlGateway" # Drop Service Account Logons
#================================ General =====================================

# The name of the shipper that publishes the network data. It can be used to group
# all the transactions sent by a single shipper in the web interface.
#name:

# The tags of the shipper are included in their own field with each
# transaction published.
#tags: ["service-X", "web-tier"]

# Optional fields that you can specify to add additional information to the
# output.
#fields:
#  env: staging

#================================ Outputs =====================================

# Configure what outputs to use when sending the data collected by the beat.
# Multiple outputs may be used.

#-------------------------- Elasticsearch output ------------------------------
#output.elasticsearch:
  # Array of hosts to connect to.
  #hosts: ["elasticsearch:9200"]

  # Optional protocol and basic auth credentials.
  #protocol: "https"
  #username: "elastic"
  #password: "changeme"

#----------------------------- Logstash output --------------------------------
output.logstash:
  # The Logstash hosts
  hosts: ["uselp01:5045","uselp02:5045","uselp03:5045"]
  loadbalance: true

  # Optional SSL. By default is off.
  # List of root certificates for HTTPS server verifications
  #ssl.certificate_authorities: ["/etc/pki/root/ca.pem"]

  # Certificate for SSL client authentication
  #ssl.certificate: "/etc/pki/client/cert.pem"

  # Client Certificate Key
  #ssl.key: "/etc/pki/client/cert.key"

#================================ Logging =====================================

# Sets log level. The default log level is info.
# Available log levels are: critical, error, warning, info, debug
#logging.level: debug

# At debug level, you can selectively enable logging only for some components.
# To enable all selectors use ["*"]. Examples of other selectors are "beat",
# "publish", "service".
#logging.selectors: ["*"]

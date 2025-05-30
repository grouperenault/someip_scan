# a SOME/IP scanner based on Scapy

version 0.4

laurent.clevy-extern@ampere.cars


## Requirements

- Scapy 2.6.1
- Python 3.10

Tested under Ubuntu 22.04

You need to have your computer connected to the ECU with the proper network configuration : sometimes custom source MAC address, specific VLAN ID and IP network.

## Features

- detects SOME/IP services and methods by bruteforce, and often minimal payload length
- listen SD packets to optimize bruteforcing (planned)
- services id and method id ranges can be specified.
    - default range for service scan is '1-50,127,128'
    - default range for method scan is '1-32,0x8001-0x8020
- display services name, methods name if defined in AIVC.py (here for In-Vehicule-Connectivity ECU). You can specify them for any ECU.   
- dumps known responses defined in AIVC.py (or other ECU)

SOME/IP protocol and this scanner are described in french magazine MISC:
- https://connect.ed-diamond.com/misc/mischs-032

## Limitations

- only TCP transport. SOME/IP-TP is not supported (and not planned).


## Usage

```bash
$ python3 someip_scan.py -h
usage: someip_scan [-h] -a ADDR [-s SRANGE] [-m MRANGE] [-i INTF] [-u UDP] [-t TCP] [-l] [-c] [-d]

options:
  -h, --help            show this help message and exit
  -a ADDR, --addr ADDR  IP address of the service
  -s SRANGE, --srange SRANGE
                        service ID range
  -m MRANGE, --mrange MRANGE
                        method ID range
  -i INTF, --intf INTF  network interface to reach the service
  -u UDP, --udp UDP     UDP port
  -t TCP, --tcp TCP     TCP port
  -l, --listen          listen to SD packets
  -c, --confidential    do not display services and methods names
  -d, --dump            dump / parses known responses


```

### Services bruteforce method

The only required parameter is -a for the SOME/IP server, here 192.168.61.3:

```bash
$ python3 someip_scan.py -a 192.168.61.3 
Scanning services range 1-50,127,128, methods range 1-32, server 192.168.61.3, port 30501

service 0x1e/30 detected
service 0x21/33 detected
service 0x24/36 detected
service 0x25/37 detected
service 0x27/39 detected
service 0x28/40 detected
service 0x7f/127 detected

Scan summary:
Service Method Type Payload_len Service_name/Method_name
   30     1     RR       0      Connection_InitialSequence/Configuration_Get
   30     2     RR       6      Connection_InitialSequence/NAV_ID_Info_Get
   30     3     FF      13      Connection_InitialSequence/
   30     4     FF       ?      Connection_InitialSequence/
   33     1     RR       0      Connectivity_ModemStatus/Modem_Status_Get
   36     2     RR       0      
   36     1     FF       1      
   37     1     FF       ?      
   37     2     FF       ?      
   37     3     FF       ?      
   39     2     RR       7      
   39     3     RR       1      
   39     1     FF       7      
   40     1     RR       1      
  127     1     RR    1037      

```

### Responses parsing

with the -d option (dump) known responses are dumped:

```bash
$ python3 someip_scan.py -a 192.168.61.3 -d
Scanning services range 1-50,127,128, methods range 1-32, server 192.168.61.3, port 30501

service 0x1e/30 detected
    detected_rr_methods 30 1
      response is:  b'"\x01\x00\x00\x00'
    detected_rr_methods 30 2
###[ AIVC NAV_ID_Info_Status ]###
  Invalid_Parameter= 0
  TCU_ID    = b'V[     redacted    ]6'
  ICC_ID    = b'8[     redacted    ]0'
  VIN       = b'V[   redacted  ]3'

  Operator_Service= 0
  Connected_Search= 0
  Mobile_Information= 0
  Internet_Widget= 1
  Fuel_Price= 0
  Local_Search= 0
  Web_Pre_Trip= 0
  HD_Traffic= 0
  Speed_Trap= 0
  Prevent_NAV= 0
  Weather   = 0
  Live_Services= 1
  Charging_Spot_Finder= 0
  Charging_Scheduler= 0

service 0x21/33 detected
    detected_rr_methods 33 1
      response is:  b'\x03\x01\[redacted]]\x03'
service 0x24/36 detected
    detected_rr_methods 36 2
      response is:  b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
service 0x25/37 detected
service 0x27/39 detected
    detected_rr_methods 39 2
      response is:  b'\x02'
    detected_rr_methods 39 3
      response is:  b'\x02'
service 0x28/40 detected
    detected_rr_methods 40 1
      response is:  b'\x00'
service 0x7f/127 detected
    detected_rr_methods 127 1

Scan summary:
Service Method Type Payload_len Service_name/Method_name
   30     1     RR       0      Connection_InitialSequence/Configuration_Get
   30     2     RR       6      Connection_InitialSequence/NAV_ID_Info_Get
   30     3     FF      13      Connection_InitialSequence/
   30     4     FF       ?      Connection_InitialSequence/
   33     1     RR       0      Connectivity_ModemStatus/Modem_Status_Get
   36     2     RR       0      
   36     1     FF       1      
   37     1     FF       ?      
   37     2     FF       ?      
   37     3     FF       ?      
   39     2     RR       7      
   39     3     RR       1      
   39     1     FF       7      
   40     1     RR       1      
  127     1     RR    1037      

```



### Service Discovery Listen method

use -l option.

```bash
$ sudo -E python3 someip_scan.py -a 192.168.61.3 -l
[sudo] password for laurent: 
Listening to Service Discovery from host 192.168.61.3
detected_sd: {'sport': 30490, 'dport': 30490, 'macsrc': '[redacted]:00:03', 'macdst': '01:00:[redacted]', 'srv_id': 65535, 'sub_id': 33024, 'port': 30501, 'l4_proto': 6, 'offered_services': {33, 36, 37, 39, 40, 30, 127}} 

Scanning services range 1-50,127,128, methods range 1-32, server 192.168.61.3, port 30501

service 0x1e/30 detected
service 0x21/33 detected
service 0x24/36 detected
service 0x25/37 detected
service 0x27/39 detected
service 0x28/40 detected
service 0x7f/127 detected

Scan summary:
Service Method Type Payload_len Service_name/Method_name
   30     1     RR       0      Connection_InitialSequence/Configuration_Get
   30     2     RR       6      Connection_InitialSequence/NAV_ID_Info_Get
   30     3     FF      13      Connection_InitialSequence/
   30     4     FF       ?      Connection_InitialSequence/
   33     1     RR       0      Connectivity_ModemStatus/Modem_Status_Get
   36     2     RR       0      
   36     1     FF       1      
   37     1     FF       ?      
   37     2     FF       ?      
   37     3     FF       ?      
   39     2     RR       7      
   39     3     RR       1      
   39     1     FF       7      
   40     1     RR       1      
  127     1     RR    1037      

SD services and scanned services sets are identical.

```


## TODO / Ideas

- UDP scans
- fake Service Discovery with a lot of services offered, to catch clients
- detect Subscribe / Event type services

'''
someip_scan.py

SOME/IP scanner

- detects Request & Response, Fire and forget methods
- detect valid payload lengths
- only TCP now
- listen to SD offer packet and compare with scanned services

version 0.4

laurent.clevy-extern@ampere.cars
'''

from scapy.packet import Packet, Raw
from scapy.sendrecv import sniff
from scapy.contrib.automotive.someip import SOMEIP, SD, SDEntry_Service, SDEntry_EventGroup, SDOption_IP4_SD_EndPoint

import sys 
import socket
import struct 
import argparse
from random import randint, randbytes
from time import sleep
from binascii import unhexlify

try:
  from AIVC import AIVC_NAV_ID_Info_Status, AIVC_services
  known_methods_responses = { '30_2': AIVC_NAV_ID_Info_Status }

except ModuleNotFoundError:
  print('AIVC.py is missing, dump option will fail')

#convert a decimal or hexa number from string to int
def str2int(s):
  if s.lower().find('0x')==0:
    try:
      i = int(s, 16)
    except ValueError:
      return None
  else:
    try:
      i = int(s)
    except ValueError:
       return None
  return i       

#convert a range to enumeration
def range2list( r ):
  _range = []
  l = r.split(',')

  for e in l:
    try:
      if e.find('-')>0:
        r2 = e.split('-')
        if len(r2)!=2:
          return None
        s = str2int(r2[0])
        e = str2int(r2[1])
        if s is None or e is None:
          return None
        l2 = list(range(s,e+1)) #enumerate s-e 
        _range.extend(l2)
      else:
        v = str2int(e)
        if v is None:
          return None
        _range.append(v)
    except ValueError:
      return None
  return _range      

MAX_RESPONSE = 2048

session_id = 0


def send_and_recv( s, service, method_id, payload_len=0, payload=None ):
  global session_id
  someip = SOMEIP( srv_id=service, sub_id=method_id, session_id=session_id, iface_ver=1, proto_ver=1, msg_type="REQUEST", retcode='E_OK'  )
  #someip.show()
  if payload:
    someip.add_payload( Raw(payload) )    
  elif payload_len > 0:
    someip.add_payload( Raw(b'\x00'*payload_len) )

  s.send( someip.build() )
  try:
    ans = s.recv(MAX_RESPONSE)
  except TimeoutError:
    #print('    TimeoutError s%d m%d p%d' % (service, method_id, payload_len))
    return 'TimeoutError'
  except ConnectionResetError:
    print('method', method_id )
    return 'ConnectionResetError'
  someip_ans = SOMEIP(ans)
  #someip_ans.show()
  #assert someip_ans.session_id == session_id
  session_id += (session_id + 1) & 0xFFFF #on 16 bits

  return someip_ans

TCP_TIMEOUT = 1

#setup a TCP connection
def connect(ip_service, port, intf=None):
  global s
  s = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 
  s.settimeout(TCP_TIMEOUT)
  if intf:
    s.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, intf)

  try:
    s.connect((ip_service,port))
    return s
  except ConnectionRefusedError:
    print('ConnectionRefusedError')
    sys.exit()

#add first element e to a list, the latter being an entry to dictionnary d, with index i
def addElementSet2Dict(d, i, e):
  if i not in d:
    d[ i ] = set()
  d[ i ].add( e )


#setup udp socket
def bind( port ):
  s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) 
  s.settimeout(TCP_TIMEOUT)
  s.bind( ( '', port ) ) # source port: mandatory, as ACK will be sent here
  return s

def sdPacket( s, service_id, eventgroup, client, server, ttl ):
  global session_id
  ### subscribe to 
  sip = SOMEIP( session_id=session_id, iface_ver=1, proto_ver=1, msg_type="NOTIFICATION", retcode="E_OK")

  sd = SD( flags=0xc0 ) #reboot and unicast flags

  #eg = SDEntry_EventGroup(... res=0x008) #res=0x008 initial event request = True
  eg = SDEntry_EventGroup( srv_id=service_id, eventgroup_id = eventgroup, n_opt_1 = 1, inst_id = 1, ttl=ttl, major_ver=1)
  sd.set_entryArray(eg)

  oa = SDOption_IP4_SD_EndPoint(type=4, addr = client, l4_proto = 6, port = args.tcp)
  sd.set_optionArray(oa)

  #s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) 
  #s.settimeout(TCP_TIMEOUT)
  #s.bind(('',args.udp)) # source port: mandatory, as ACK will be sent here
  s.sendto( (sip / sd).build(), (server, args.udp) )

  #wait for subscribe ack
  try: 
    ans, addr = s.recvfrom( 1024 )
    #s.close()
    #print('received answer from', addr)
  except TimeoutError:
    print('sdPacket recvfrom TimeoutError')
    return None

  sip = SOMEIP(ans)
  #assert sip.session_id == session_id
  session_id = (session_id + 1) & 0xFFFF #on 16 bits
  #sip.show()
  return sip


PAYLOAD_MAXSIZE = 1040 #type PrivacySetting_t of GranularPrivacy service is about 840 bytes

parser = argparse.ArgumentParser( prog='someip_scan' )
parser.add_argument('-a', '--addr', help='IP address of the service', action='store', type=str, required=True) 
parser.add_argument('-s', '--srange', help='service ID range', action='store', type=str, default='1-50,127,128') 
parser.add_argument('-m', '--mrange', help='method ID range', action='store', type=str, default='1-32') 
parser.add_argument('-i', '--intf', help='network interface to reach the service', action='store', type=str, default='enx002.610')
parser.add_argument('-u', '--udp', help='UDP port', default=30490) 
parser.add_argument('-t', '--tcp', help='TCP port', default=30501) 
parser.add_argument('-l', '--listen', help='listen to SD packets', action='store_true' ) 
parser.add_argument('-c', '--confidential', help='do not display services and methods names', action='store_true' ) 
parser.add_argument('-d', '--dump', help='dump / parses known responses', action='store_true' )

args = parser.parse_args()

ip_service = args.addr.encode()
port = int(args.tcp)

srange = range2list(args.srange)
mrange = range2list(args.mrange)

session_id = 1


detected_sd = dict()

if args.listen and args.intf:
  print('Listening to Service Discovery from host %s' % args.addr)

  try:
    packets = sniff( iface=args.intf, filter='host '+args.addr, count=1)
    detected_sd[ 'sport' ] = packets[0].sport
    detected_sd[ 'dport' ] = packets[0].dport
    detected_sd[ 'macsrc' ] = packets[0].src
    detected_sd[ 'macdst' ] = packets[0].dst
    detected_sd[ 'srv_id' ] = packets[0].srv_id
    detected_sd[ 'sub_id' ] = packets[0].sub_id
    detected_sd[ 'port' ] = packets[0].option_array[0][0].port
    detected_sd[ 'l4_proto' ] = packets[0].option_array[0][0].l4_proto

    detected_sd[ 'offered_services' ] = set()
    for e in packets[0].entry_array:
      detected_sd[ 'offered_services' ].add( e.srv_id )

    print('detected_sd:', detected_sd, '\n')

  except PermissionError:
    print('Can not sniff the network, root rights are required. Use sudo -E python3 ...\n')
    sys.exit()

def display_method(d, s, m, mtype):
  method_index = '%d_%d' % (s, m)
  service_name = ''
  method_name = ''
  if s in AIVC_services:
    service_name = AIVC_services[s][0]['service'] #at least one method per service described
    for method in AIVC_services[s]:
      if method['type'] == 'method' and m == method['id']:
        method_name = method['message_name']
  if args.confidential:
    service_description = ''
  else:  
    if service_name:
      service_description = '%s/%s' % (service_name, method_name)
    else:
      service_description = '%s' % (service_name)

  if method_index in d:
    print('%5d %5d     %s    %4d      %s' %(s, m, mtype, d[method_index], service_description ))
  else:
    print('%5d %5d     %s       ?      %s' %(s, m, mtype, service_description))  


def send_someip(s, someip):
  s.send( someip.build() )
  try:
    ans = s.recv(MAX_RESPONSE)
  except TimeoutError:
    #print('    TimeoutError s%d m%d p%d' % (service, method_id, payload_len))
    return 'TimeoutError'
  someip_ans = SOMEIP(ans)
  #assert someip_ans.session_id == session_id
  #session_id += 1

  return someip_ans


DEFAULT_METHOD_ID = 666

detected_services = set()
no_services = []
detected_rr_methods = dict()
detected_ff_methods = dict()
no_methods = dict()
detected_payloads = dict()
payload_len = 0
method_id = 1
responses = dict()
timeout = dict()

print('Scanning services range %s, methods range %s, server %s, port %d\n' % (args.srange, args.mrange, args.addr, port))


s = connect(ip_service, port)


for service in srange:

      someip_ans = send_and_recv( s, service, DEFAULT_METHOD_ID, 0 ) #is method_id checked also to answer known_service?
      method_index = '%d_%d' % (service, method_id)
      if someip_ans == 'TimeoutError':
        continue
      if someip_ans.retcode == SOMEIP.RET_E_UNKNOWN_SERVICE:
        continue

      detected_services.add( service )
      print( 'service 0x%x/%d detected' % (service,service) )

      for method_id in mrange:

        someip_ans = send_and_recv( s, service, method_id, 0)
        method_index = '%d_%d' % (service, method_id)
        if someip_ans == 'TimeoutError' :
          addElementSet2Dict(detected_ff_methods, service, method_id)
          continue

        elif someip_ans.retcode == SOMEIP.RET_E_UNKNOWN_METHOD:
          continue

        for payload_len in range(PAYLOAD_MAXSIZE+1):
          someip_ans = send_and_recv( s, service, method_id, payload_len)

          #some Fire and Forget methods times out only with correct payload length
          if someip_ans == 'TimeoutError':
            timeout[method_index] = payload_len
            addElementSet2Dict(detected_ff_methods, service, method_id)
            # some methods are first seen as Request and Response, remove from detected_rr_methods
            if service in detected_rr_methods and method_id in detected_rr_methods[ service ]:
              detected_rr_methods[ service ].remove( method_id )
            break

          if someip_ans.retcode != SOMEIP.RET_E_UNKNOWN_METHOD: #method detected
            addElementSet2Dict(detected_rr_methods, service, method_id)            

            if someip_ans.retcode != SOMEIP.RET_E_MALFORMED_MSG: #correct payload length detected
              addElementSet2Dict(detected_rr_methods, service, method_id)

              detected_payloads[ method_index ] = payload_len
              if args.dump:
                print('    detected_rr_methods', service, method_id)
                #print(someip_ans)
                #someip_ans.show()
                
                if method_index in known_methods_responses:
                  known_methods_responses[ method_index ](someip_ans.load).show()
                else:
                  try:
                    print('      response is: ', someip_ans.load)
                  except AttributeError:
                    pass  
              try:
                responses[ method_index ] = (payload_len, someip_ans.load)
              except (ValueError, AttributeError) as e: #answer from method 1 of service 127 has no payload
                responses[ method_index ] = (payload_len, None)                
              break


print('\nScan summary:\nService Method Type Payload_len Service_name/Method_name')
for s in sorted(detected_services):
  if s in detected_rr_methods:
    for m in detected_rr_methods[s]:
      display_method( detected_payloads, s, m, 'RR' )
      if s in AIVC_services:
        for m2 in AIVC_services[s]:
          if m2['method_id'] == m: 
            if m2['sending'] != 'RR':
              print('               service', s, 'method', m, 'is theoricaly',  m2['sending'])   
  if s in detected_ff_methods:    
    for m in detected_ff_methods[ s ]:
      display_method( timeout, s, m, 'FF' )
      if s in AIVC_services:
        for m2 in AIVC_services[s]:
          if m2['method_id'] == m: 
            if m2['sending'] != 'FF':
              print('               service', s, 'method', m, 'is theoricaly',  m2['sending'])   


if args.listen:
  diff = detected_services.difference( detected_sd[ 'offered_services' ] )
  if diff:
    print('\nSD services set is different than scanned services set: ', diff)
  else:
    print('\nSD services and scanned services sets are identical.')

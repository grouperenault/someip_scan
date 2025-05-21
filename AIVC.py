#AIVC.py

from scapy.packet import Packet
from scapy.fields import ByteEnumField, ByteField, StrFixedLenField, ShortField, LongField, FieldLenField, FieldListField, PadField

from struct import Struct

AIVC_services = { 
  30: [ 
    { 'message_name':'Configuration_Get', 'service':'Connection_InitialSequence', 'type':'method', 'id':1, 'method_id':1, 'sending':'RR' }, 
    { 'message_name':'NAV_ID_Info_Get', 'service':'Connection_InitialSequence', 'type':'method', 'id':2, 'method_id':2, 'sending':'RR' },
      ],
  33: [ 
    { 'message_name':'Modem_Status_Get', 'service':'Connectivity_ModemStatus', 'type':'method', 'id':1, 'method_id':1, 'sending':'RR' },
    ] 

 }



class AIVC_NAV_ID_Info_Status(Packet):
  name = "AIVC NAV_ID_Info_Status"
  fields_desc = [
    ByteField("Invalid_Parameter", None ), 
    StrFixedLenField("TCU_ID", None, length=20),
    StrFixedLenField("ICC_ID", None, length=20),
    StrFixedLenField("VIN", None, length=17),    

    ByteField("Operator_Service", None), 
    ByteField("Connected_Search", None), 
    ByteField("Mobile_Information", None), 
    ByteField("Internet_Widget", None),     
    ByteField("Fuel_Price", None), 
    ByteField("Local_Search", None), 
    ByteField("Web_Pre_Trip", None), 
    ByteField("HD_Traffic", None),                 
    ByteField("Speed_Trap", None),  
    ByteField("Prevent_NAV", None),  
    ByteField("Weather", None),  
    ByteField("Live_Services", None),  
    ByteField("Charging_Spot_Finder", None),  
    ByteField("Charging_Scheduler", None)     
  ] 
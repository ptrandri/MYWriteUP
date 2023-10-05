#!/usr/bin/env python3
from cortexutils.responder import Responder
import requests
import ipaddress
import json
import urllib3
from base64 import b64encode

# Disable insecure https warnings (for self-signed SSL certificates)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class Wazuh(Responder):
   def __init__(self):
       Responder.__init__(self)
       self.wazuh_manager = self.get_param('config.wazuh_manager', None, 'https://localhost:55000')
       self.wazuh_user = self.get_param('config.wazuh_user', None, 'Username missing!')
       self.wazuh_password = self.get_param('config.wazuh_password', None, 'Password missing!')
       self.wazuh_agent_id = self.get_param('data.case.customFields.wazuh-agent-id.string', None, "Agent ID Missing!")
       self.wazuh_alert_id = self.get_param('data.case.customFields.wazuh-alert-id.string', None, "Alert ID Missing!")
       self.wazuh_rule_id = self.get_param('data.case.customFields.wazuh-rule-id.string', None, "Rule ID Missing!")
       self.observable = self.get_param('data.data', None, "Data is empty")
       self.observable_type = self.get_param('data.dataType', None, "Data type is empty")
   
   def run(self):
       Responder.run(self)
       auth = (self.wazuh_user, self.wazuh_password)
       basic_auth = f"{self.wazuh_user}:{self.wazuh_password}".encode()
       headers = {'Content-Type': 'application/json',
                 'Authorization': f'Basic {b64encode(basic_auth).decode()}'}
       
       # Check observable to ensure valid IP address
       if self.observable_type == "ip":
           try:
               ipaddress.ip_address(self.observable)
           except ValueError:
               self.error({'message': "Not a valid IPv4/IPv6 address!"})
       else: 
           self.error({'message': "Not a valid IPv4/IPv6 address!"})
#      payload = '{"command":"firewall-drop180", "arguments": ["-", "' +  self.observable + '", "' + self.wazuh_alert_id + '", "' + self.wazuh_rule_id + '", "' + self.wazuh_agent_id + '", "var/log/test.log"]}'
       payload ='{"command": "firewall-drop180","alert": {"data": {"srcip": "' +  self.observable + '", "alert_id": "' + self.wazuh_alert_id + '", "rule_id": "' + self.wazuh_rule_id + '", "agent_id": "' + self.wazuh_agent_id + '", "log_path": "/var/log/test.log"}}}'

       response = requests.get(self.wazuh_manager + '/security/user/authenticate', headers=headers, verify=False)
       token = json.loads(response.content.decode())['data']['token']
       # New authorization header with the JWT token we got
       requests_headers = {'Content-Type': 'application/json',
                          'Authorization': f'Bearer {token}'}

       response = requests.put(f"{self.wazuh_manager}/active-response?agents_list={self.wazuh_agent_id}", headers=requests_headers, data=payload, verify=False)
       
       if response.status_code == 200:
           self.report({'message': "Added DROP rule for " + self.observable  })
       else:
           self.error(response.status_code)
   
   def operations(self, raw):
      return [self.build_operation('AddTagToCase', tag='Wazuh: Blocked IP')] 

if __name__ == '__main__':
  Wazuh().run()
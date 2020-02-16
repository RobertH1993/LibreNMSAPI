# LibreNMSAPI
A Python API client library for (https://www.librenms.org/ "LibreNMS").  
LibreNMS is a fully featured network monitoring system that provides a wealth of features and device support.  

## Installation
Add the folder LibreNMSAPI to your project this way it can be used as module  

## Quick start
To begin import the API and create an instance of the LibreNMSAPI class  

``` python
from LibrenmsAPI.LibreNMSAPI import LibreNMSAPI

# Do not use a trailing slasg for the URL
api = librenmsAPI(
  token = "token"
  url= "https://librenms.example.com/api/v0"
)
```

## Queries
You can reach all endpoints inside the LibreNMS API by calling there routes as attribute of the LibreNMSAPI instance.  
All queries return an Endpoint that can again be queried and in some cases contain the data from the queries endpoint (if any).  
For example:  

``` python
all_devices = api.devices.all()
for device in devices:
  print(device.device_id)

specific_device = api.devices.get("s01.example.com")
if specific_device:
  print(device.device_id)

specific_device.delete()
```
## Contributing
If you want to contribute please fork this project, push your changes and send a pull request.  



Usage:

from LibrenmsAPI.LibreNMSAPI import LibreNMSAPI

api = LibreNMSAPI("token", "url-without-trailing-slash")

devices = api.devices.all()
device_by_id = api.devices.get("1")
device_by_hostname = api.device.get("server.example.com")

all_ports = api.ports.all()

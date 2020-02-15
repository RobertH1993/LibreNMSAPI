# LibreNMSAPI
Python libreNMS API

Usage:
from LibrenmsAPI.LibreNMSAPI import LibreNMSAPI

api = LibreNMSAPI("token", "url-without-trailing-slash")

devices = api.devices.all()
device_by_id = api.devices.get("1")
device_by_hostname = api.device.get("server.example.com")

all_ports = api.ports.all()

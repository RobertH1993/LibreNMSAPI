#!/bin/python
import requests
import json
import os

class LibreNMSInvalidendpointException(Exception):
	def __init__(self, message):
		super(LibreNMSInvalidendpointException, self).__init__(message)


class LibreNMSStatusNotOKException(Exception):
	def __init__(self, message):
		super(LibreNMSStatusNotOKException, self).__init__(message)


class LibreNMSDataExtractionFailedException(Exception):
	def __init__(self, message):
		super(LibreNMSDataExtractionFailedException, self).__init__(message)


class LibreNMSJsonNormalizer():
	def __init__(self):
		pass

	def _extract_root_endpoint_objects(self, json, endpoint):
		objects_key = endpoint
		if endpoint == "devicegroups":
			objects_key = "groups"
		elif endpoint == "bgp":
			objects_key = "bgp_sessions"

		if objects_key not in json:
			objects_key = None

		singular = endpoint[:-1]
		if singular in json:
			return json[singular]

		return json[objects_key]

	def _extract_endpoint_objects(self, json, endpoint):
		root_endpoint = endpoint.split("/")[0]
		singular_root_endpoint = root_endpoint[:-1]

		if root_endpoint in json:
			return json[root_endpoint]
		elif singular_root_endpoint in json:
			return json[singular_root_endpoint]
		elif 'graphs' in json:
			return json['graphs']
		elif 'addresses' in json:
			return json['addresses']
		elif 'devices' in json:
			return json['devices']

		return None

	def _is_root_endpoint(self, endpoint):
		if len(endpoint.split('/')) == 1:
			return True

		return False

	def get_json_data(self, json, endpoint):
		if self._is_root_endpoint(endpoint):
			objects = self._extract_root_endpoint_objects(json, endpoint)
		else:
			objects = self._extract_endpoint_objects(json, endpoint)

		if not objects:
			objects = []

		return objects

	def get_json_id_keyname(self, json_objects, endpoint):
		if len(json_objects) == 0:
			return None

		first_object = json_objects[0]
		keyname = None
		if 'id' in first_object:
			return 'id'

		singular = endpoint[:-1]
		if "{}_id".format(singular) in first_object:
			keyname = "{}_id".format(singular)

		if "event_id" in first_object:
			keyname = "event_id"

		return keyname


class LibreNMSendpoint:
	valid_endpoints = {
	"alerts": {
			"alerts": ['GET',], #list_alerts
			"alerts/{digit}": ['GET','PUT'], #get_alerts,ack_alerts
			"alerts/unmute/{digit}": ['PUT'], #unmute_alert
		},
		"bgp": {
			"bgp": ['GET'], #list_bgp
			"bgp/{digit}": ['GET','POST'], #get_bgp,edit_bgp_descr (:id)
		},
		
		"bills": {
			"bills": ['GET','POST','DELETE'], #list_bills,create_edit_bill,delete_bill
			"bills/{digit}": ['GET'], #get_bill (:id)
		"bills/{digit}/graphs": ['GET'], #get_bill_graph
		"bills/{digit}/graphs/{nondigit}":['GET'], #get_bill_graph (:graph_type)
		"bills/{digit}/graphdata": ['GET'], #get_bill_graphdata
		"bills/{digit}/graphdata/{nondigit}": ['GET'], #get_bill_graphdata (:graph_type)
		"bills/{digit}/history": ['GET'], #get_bill_history
		"bills/{digit}/history/{digit}/graphs": ['GET'], #get_bill_history_graph
		"bills/{digit}/history/{digit}/graphs/{nondigit}": ['GET'], #get_bill_history_graph (:graph_type)
			"bills/{digit}/history/{digit}/graphdata": ['GET'], #get_bill_history_graph
		"bills/{digit}/history/{digit}/graphdata/{nondigit}": ['GET'] #get_bill_history_graph (:graph_type)
		},
		"devices" : {
			"devices": ['GET', 'POST', 'DELETE', 'PATCH'], #list_devices,add_device,del_device,update_device_field
			"devices/{string}" : ['GET'], #get_device
			"devices/{string}/discover": ['GET'], #discover_device
			"devices/{string}/availability": ['GET'], #availability
			"devices/{string}/outages": ['GET'], #outages
			"devices/{string}/graphs": ['GET'], #get_graphs
			"devices/{string}/health": ['GET'], #list_available_health_graphs
			"devices/{string}/health/{nondigit}": ['GET'], #list_available_health_graphs (/:type)
			"devices/{string}/health/{nondigit}/{digit}": ['GET'], #list_available_health_graphs (/:type/:sensor_id)
			"devices/{string}/wireless/{nondigit}": ['GET'], #list_available_wireless_graphs (/:type)
			"devices/{string}/wireless/{nondigit}/{digit}": ['GET'], #list_available_wireless_graphs (/:type/:sensor_id)
			"devices/{string}/graphs/health/{nondigit}": ['GET'],  #get_health_graph
			"devices/{string}/graphs/health/{nondigit}/{digit}": ['GET'],  #get_health_graph (/:sensor_id)
			"devices/{string}/graphs/wireless/{nondigit}": ['GET'], #get_wireless_graph
			"devices/{string}/graphs/wireless/{nondigit}/{digit}": ['GET'], #get_wireless_graph (/:sensor_id)
			"devices/{string}/{nondigit}": ['GET'], #get_graph_generic_by_string
			"devices/{string}/ports": ['GET'], #get_port_graphs
			"devices/{string}/fdb": ['GET'], #get_device_fdb
			"devices/{string}/ip": ['GET'], #get_device_ip_addresses
			"devices/{string}/port_stack": ['GET'], #get_port_stack
			"devices/{string}/components": ['GET','PUT'], #get_components, edit_components
			"devices/{string}/components/{nondigit}": ['POST'], #add_components
			"devices/{string}/components/{digit}": ['DELETE'], #delete_components
			"devices/{string}/ports/{nondigit}": ['GET'], #get_port_stats_by_port_string
			"devices/{string}/ports/{nondigit}/{nondigit}": ['GET'], #get_graph_by_port_string
			"devices/{string}/maintenance": ['POST'], #maintenance_device
			"devices/{string}/port/{digit}": ['PATCH'], #update_device_port_notes
			"devices/{string}/rename/{nondigit}": ['PATCH'], #rename_device
			"devices/{string}/groups": ['GET'], #get_device_groups
			"devices/{string}/parents":['POST','DELETE'], #add_parents_to_host,delete_parents_from_host
			"devices/{string}/vlans": ['GET'], #get_vlans
			"devices/{string}/links": ['GET'], #get_links
		},
		
	"devicegroups": {
			"devicegroups": ['GET','POST'], #get_devicegroups,add_devicegroup
			"devicegroups/{nondigit}": ['GET'], #get_devices_by_group
			"devicegroups/{nondigit}/maintenance": ['POST'], #maintenance_devicegroup
		},
		
	"inventory": {
			"inventory": ['GET'], #get_inventory
			"inventory/{string}/all": ['GET'] #get_inventory_for_device
		},
	"locations": {
		"locations" : ['POST'], #add_location
		"locations/{nondigit}" : ['PATCH','DELETE'], #edit_location, delete_location
	},
		
		"logs": {
			"logs/eventlog": ['GET'], #list_eventlog
			"logs/eventlog/{string}": ['GET'], #list_eventlog (:hostname)
			"logs/syslog": ['GET'],	#list_syslog
			"logs/syslog/{string}": ['GET'], #list_syslog (:hostname)
			"logs/alertlog": ['GET'], #list_alertlog
			'logs/alertlog/{string}': ['GET'], #list_alertlog (:hostname)
			"logs/authlog": ['GET'], #list_authlog
			"logs/authlog/{string}": ['GET'], #list_authlog (:hostname)
		},	
		"ospf": {
			"ospf": ['GET'], #list_ospf
		},
		"ospf_ports": {
			"ospf_ports": ['GET'], #list_ospf_ports
		},
		"oxidized": {
			"oxidized": ['GET'], #list_oxidized
			"oxidized/{nondigit}": ['GET'], #list_oxidized (/:hostname)
			"oxidized/config/search/{nondigit}": ['GET'], #search_oxidized
			"oxidized/config/{nondigit}": ['GET'], #get_oxidized_config
		},
		"ports": {
			"ports": ['GET'], #get_all_ports
			"ports/search/{string}": ['GET'], #search_ports
		"ports/search/{string}/{string}":['GET'], #search_ports in specific column
		"ports/mac/{string}":['GET'], #ports_with_associated_mac
			"ports/{digit}": ['GET'], #get_port_info
			"ports/{digit}/ip": ['GET'], #get_port_ip_info
		},
	"port_groups":{
		"port_groups":['GET','POST'], #get_port_groups,add_port_group
		"port_groups/{nondigit}":['GET'], #get_ports_by_group
		"port_groups/{digit}/assign":['POST'], #assign_port_group
		"port_groups/{digit}/remove":['POST'], #remove_port_group
	},
		"portgroups": {
			"portgroups": ['GET'], #get_graph_by_portgroup
		"portgroups/{string}":['GET'], #get_graph_by_portgroup (:group)
			"portgroups/multiports/bit": ['GET'], #get_graph_by_portgroup_multiport_bits
			"portgroups/multiports/bit/{string}": ['GET'], #get_graph_by_portgroup_multiport_bits (:id/s)
		},
		"resources": {
			"resources/links": ['GET'],
			"resources/locations": ['GET'], #list_locations
		"resources/sensors": ['GET'], #list_sensors
		"resources/ip/arp/{nondigit}": ['GET'], #list_arp
			"resources/ip/addresses": ['GET'], #list_ip_addresses
			"resources/ip/networks/{digit}/ip": ['GET'], #get_network_ip_addresses
		"resources/ip/networks": ['GET'], #list_ip_networks
			"resources/fdb":  ['GET'], #list_fdb
			"resources/fdb/{string}":  ['GET'], #list_fdb (:mac)
			"resources/links/": ['GET'], #list_links
			"resources/vlans": ['GET'], #list_vlans
		},

		"routing": {
			"routing/vrf": ['GET'], #list_vrf
			"routing/vrf/{digit}": ['GET'], #get_vrf (:id)
			"routing/ipsec/data": ['GET'], #list_ipsec
			"routing/ipsec/data/{string}": ['GET'], #list_ipsec (:hostname)
			"routing/bgp/cbgp": ['GET'],  #list_cbgp
		"routing/mpls/services": ['GET'], #list_mpls_services
		"routing/mpls/saps": ['GET'], #list_mpls_saps
		},
		
		"rules": {
		"rules/{digit}": ['GET','DELETE'], #get_alert_rule,delete_rule (:id)
			"rules": ['GET','POST','PUT'], #list_alert_rules, add_rule, edit_rule
		},
		"services": {
			"services": ['GET'], #list_services
			"services/{string}": ['GET','POST','PATCH','DELETE'], #get_service_for_host,add_service_for_host,edit_service_from_host,delete_service_from_host (:hostname)
		},
	"system":{
		"system":['GET'], #system
	}
	}

	def __init__(self, endpoint_name, api_access_token, base_apiurl, data=None):
		self._normalizer = LibreNMSJsonNormalizer()
		self._endpoint_data = {} if data is None else data
		self._endpoint_name = endpoint_name
		self._api_access_token = api_access_token
		self._base_apiurl = base_apiurl
		self._default_headers = {
			"Content-Type": "application/json",
			"Accept": "application/json",
			"X-Auth-Token": self._api_access_token
		}
		self._valid_methods = self._get_endpoint_request_methods()
		#TODO check if base url ends with trailing slash

	def _valid_response_status(self, json):
		if 'status' not in json:
			return False

		if json['status'] == "ok":
			return True

	def _valid_status_code(self, status_code):
		if status_code >= 200 and status_code <= 299:
			return True

		return False

	def _valid_response(self, response):
		if not self._valid_status_code(response.status_code):
			return False
		if not self._valid_response_status(json.loads(response.text)):
			return False

		return True

	def _create_url(self, parts):
		return "/".join(parts)

	def _get_endpoint_request_methods(self):
		splitted_endpoint = self._endpoint_name.split("/")
		if not splitted_endpoint[0] in LibreNMSendpoint.valid_endpoints:
			raise LibreNMSInvalidendpointException("endpoint does not exists")

		possible_endpoints = LibreNMSendpoint.valid_endpoints[splitted_endpoint[0]]
		for possible_endpoint in possible_endpoints.keys():
			splitted_possible_endpoint = possible_endpoint.split("/")

			# Start by filtering on length
			if len(splitted_possible_endpoint) != len(splitted_endpoint):
				continue

			found_endpoint = True
			for i in range(len(splitted_endpoint)):
				if splitted_endpoint[i] == splitted_possible_endpoint[i]:
					continue
				if splitted_possible_endpoint[i] == "{string}":
					continue
				if splitted_possible_endpoint[i] == "{digit}" and splitted_endpoint[i].isdigit():
					continue
				if splitted_possible_endpoint[i] == "{nondigit}" and not splitted_endpoint[i].isdigit():
					continue

				found_endpoint = False
				break

			if not found_endpoint:
				raise LibreNMSInvalidendpointException("endpoint {} does not exists".format(self._endpoint_name))

			return possible_endpoints[possible_endpoint]

	def all(self):
		if 'GET' not in self._valid_methods:
			raise LibreNMSInvalidendpointException("{} endpoint doesnt accept GET command".format(self._endpoint_name))

		url = self._create_url([self._base_apiurl, self._endpoint_name])
		response = requests.get(
			url,
			headers=self._default_headers
		)

		if not self._valid_response(response):
			raise LibreNMSStatusNotOKException("An error occurred while fetching endpoint")

		json_objects = self._normalizer.get_json_data(json.loads(response.text), self._endpoint_name)
		if len(json_objects) == 0:
			return []

		id_keyname = self._normalizer.get_json_id_keyname(json_objects, self._endpoint_name)
		if not id_keyname:
			raise LibreNMSDataExtractionFailedException("Cant find key to access data, did we retrieve a empty set?")

		endpoint_objects = []
		for json_object in json_objects:
			endpoint_objects.append(
				LibreNMSendpoint(
					"{}/{}".format(self._endpoint_name, json_object[id_keyname]),
					self._api_access_token,
					self._base_apiurl,
					json_object
				)
			)

		return endpoint_objects

	def get(self, object_name):
		if 'GET' not in self._valid_methods:
			raise LibreNMSInvalidendpointException("{} endpoint doesnt accept GET command".format(self._endpoint_name))

		url = self._create_url([self._base_apiurl, self._endpoint_name, object_name])
		response = requests.get(
			url,
			headers=self._default_headers
		)

		if not self._valid_response(response):
			raise LibreNMSStatusNotOKException("An error occurred while fetching endpoint")

		json_objects = self._normalizer.get_json_data(json.loads(response.text), self._endpoint_name)
		if not json_objects:
			return []

		id_keyname = self._normalizer.get_json_id_keyname(json_objects, self._endpoint_name)
		if not id_keyname:
			print(json_objects)
			raise LibreNMSDataExtractionFailedException("Failed to extract data, does endpoint or id exists?")

		json_object = json_objects[0]
		return LibreNMSendpoint(
			"{}/{}".format(self._endpoint_name, object_name),
			self._api_access_token,
			self._base_apiurl,
			data=json_object
		)

	def delete(self, object_name):
		if 'DELETE' not in self._valid_methods:
			raise LibreNMSInvalidendpointException("{} endpoint doesnt accept DELETE command".format(self._endpoint_name))

		url = self._create_url([self._base_apiurl, self._endpoint_name, object_name])
		response = requests.delete(
			url,
			headers=self._default_headers
		)

		if not self._valid_response(response):
			raise LibreNMSStatusNotOKException("An error occurred while fetching endpoints")

		return json.loads(response.text)

	def edit(self, object_name):
		if 'PUT' not in self._valid_methods:
			if 'PATCH' in self._valid_methods:
				return self.update(self,object_name)
			raise LibreNMSInvalidendpointException("{} endpoint doesnt accept PUT command".format(self._endpoint_name))

		url = self._create_url([self._base_apiurl, self._endpoint_name, object_name])
		response = requests.put(
			url,
			headers=self._default_headers
		)

		if not self._valid_response(response):
			raise LibreNMSStatusNotOKException("An error occurred while fetching endpoints")

		return json.loads(response.text)
	def update(self, object_name):
		if 'PATCH' not in self._valid_methods:
			raise LibreNMSInvalidendpointException("{} endpoint doesnt accept PATCH command".format(self._endpoint_name))

		url = self._create_url([self._base_apiurl, self._endpoint_name, object_name])
		response = requests.patch(
			url,
			headers=self._default_headers
		)

		if not self._valid_response(response):
			raise LibreNMSStatusNotOKException("An error occurred while fetching endpoints")

		return json.loads(response.text)

	def create(self, data):
		if 'POST' not in self._valid_methods:
			raise LibreNMSInvalidendpointException("{} endpoint doesnt accept POST command".format(self._endpoint_name))

		url = self._create_url([self._base_apiurl, self._endpoint_name])
		response = requests.post(
			url,
			headers=self._default_headers,
			json=data
		)

		if not self._valid_response(response):
			raise LibreNMSStatusNotOKException("An error occured while fetching endpoints")

		return json.loads(response.text)

	def test(self):
		return self._get_endpoint_request_methods()

	def __setattr__(self, key, value):
		# Dirty hack to prevent recursion..
		if key[0] == "_":
			super(LibreNMSendpoint, self).__setattr__(key, value)
		else:
			self._endpoint_data[key] = value

	def __getattr__(self, attribute_name):
		if attribute_name in self._endpoint_data.keys():
			return self._endpoint_data[attribute_name]
		else:
			return LibreNMSendpoint(
				"{}/{}".format(self._endpoint_name, attribute_name),
				self._api_access_token,
				self._base_apiurl
			)

	def __repr__(self):
		return json.dumps(self._endpoint_data)


class LibreNMSAPI:
	def __init__(self, api_access_token=None, base_apiurl=None):
		if api_access_token is None and base_apiurl is None:
			from dotenv import load_dotenv
			load_dotenv()
			self._api_access_token = os.environ['LibreNMSAPI_KEY']
			self._base_apiurl = os.environ['LibreNMSAPI_URL']
		else:
			self._api_access_token = api_access_token
			self._base_apiurl = base_apiurl

	def __getattr__(self, attribute_name):
		return LibreNMSendpoint(attribute_name, self._api_access_token, self._base_apiurl)

#!/bin/python
import requests
import json


class LibreNMSInvalidEndpointException(Exception):
    def __init__(self, message):
        super(LibreNMSInvalidEndpointException, self).__init__(message)


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


class LibreNMSEndpoint:
    valid_endpoints = {
        "bgp": {
            "bgp": ['GET'],
        },

        "ospf": {
            "ospf": ['GET'],
        },

        "oxidized": {
            "oxidized": ['GET'],
        },

        "devicegroups": {
            "devicegroups": ['GET'],
        },

        "portgroups": {
            "portgroups": ['GET'],
            "portgtoups/multiports/bit": ['GET'],
        },

        "alerts": {
            "alerts": ['GET'],
        },

        "rules": {
            "rules": ['GET'],
        },

        "services": {
            "services": ['GET'],
        },

        "resources": {
            "resources/links": ['GET'],
            "resources/locations": ['GET'],
            "resources/ip/addresses": ['GET'],
            "resources/ip/networks": ['GET'],
            "resources/ip/networks/{int}/ip": ['GET'],
            "resources/fdb":  ['GET'],
            "resources/links/": ['GET'],
            "resources/sensors": ['GET'],
            "resources/vlans": ['GET'],
        },

        "logs": {
            "logs/eventlog": ['GET'],
            "logs/eventlog/{int}": ['GET'],
            "logs/syslog": ['GET'],
            "logs/syslog/{int}": ['GET'],
            "logs/alertlog": ['GET'],
            'logs/alertlog/{int}': ['GET'],
            "logs/authlog": ['GET'],
            "logs/authlog/{int}": ['GET']
        },

        "devices": {
            "devices": ['GET', 'POST', 'DELETE', 'PATCH', 'PUT'],
            "devices/{int}": ['GET'],
            "devices/{string}": ['GET'],
            "devices/{string}/discover": ['GET'],
            "devices/{int}/discover": ['GET'],
            "devices/{string}/graphs/health/{string}": ['GET'],
            "devices/{int}/graphs/health/{string}": ['GET'],
            "devices/{string}/graphs/wireless/{string}": ['GET'],
            "devices/{int}/graphs/wireless/{string}": ['GET'],
            "devices/{string}/vlans": ['GET'],
            "devices/{int}/vlans": ['GET'],
            "devices/{string}/links": ['GET'],
            "devices/{int}/links": ['GET'],
            "devices/{string}/graphs": ['GET'],
            "devices/{int}/graphs": ['GET'],
            "devices/{string}/fdb": ['GET'],
            "devices/{int}/fdb": ['GET'],
            "devices/{string}/health/{string}": ['GET'],
            "devices/{int}/health/{string}": ['GET'],
            "devices/{string}/wireless/{string}": ['GET'],
            "devices/{int}/wireless/{string}": ['GET'],
            "devices/{string}/ports": ['GET'],
            "devices/{int}/ports": ['GET'],
            "devices/{string}/ip": ['GET'],
            "devices/{int}/ip": ['GET'],
            "devices/{string}/port_stack": ['GET'],
            "devices/{int}/port_stack": ['GET'],
            "devices/{string}/components": ['GET'],
            "devices/{int}/components": ['GET'],
            "devices/{string}/groups": ['GET'],
            "devices/{int}/groups": ['GET'],
            "devices/{string}/ports/{string}": ['GET'],
            "devices/{int}/ports/{string}": ['GET'],
        },

        "ports": {
            "ports": ['GET'],
            "ports/{int}": ['GET'],
            "ports/{int}/ip": ['GET'],
        },

        "bills": {
            "bills": ['GET'],
            "bills/{int}": ['GET'],
            "bills/{int}/graphs": ['GET'],
            "bills/{int}/graphdata": ['GET'],
            "bills/{int}/history": ['GET'],
            "bills/{int}/history/{int}/graphs": ['GET'],
            "bills/{int}/history/{int}/graphdata": ['GET'],
        },

        "routing": {
            "routing/vrf": ['GET'],
            "routing/ipsec/data": ['GET'],
            "routing/bgp/cbgp": ['GET'],
        },

        "inventory": {
            "inventory": ['GET'],
            "inventory/{string}/all": ['GET']
        },
    }

    def __init__(self, endpoint_name, access_token, base_url, data=None):
        self._normalizer = LibreNMSJsonNormalizer()
        self._endpoint_data = {} if data is None else data
        self._endpoint_name = endpoint_name
        self._access_token = access_token
        self._base_url = base_url
        self._default_headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "X-Auth-Token": self._access_token
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
        if not splitted_endpoint[0] in LibreNMSEndpoint.valid_endpoints:
            raise LibreNMSInvalidEndpointException("Endpoint does not exists")

        possible_endpoints = LibreNMSEndpoint.valid_endpoints[splitted_endpoint[0]]
        for possible_endpoint in possible_endpoints.keys():
            splitted_possible_endpoint = possible_endpoint.split("/")

            # Start by filtering on length
            if len(splitted_possible_endpoint) != len(splitted_endpoint):
                continue

            found_endpoint = True
            for i in range(len(splitted_endpoint)):
                if splitted_endpoint[i] == splitted_possible_endpoint[i]:
                    continue
                if splitted_possible_endpoint[i] == "{int}" and splitted_endpoint[i].isdigit():
                    continue
                if splitted_possible_endpoint[i] == "{string}" and not splitted_endpoint[i].isdigit():
                    continue

                found_endpoint = False
                break

            if not found_endpoint:
                raise LibreNMSInvalidEndpointException("Endpoint {} does not exists".format(self._endpoint_name))

            return possible_endpoints[possible_endpoint]

    def all(self):
        if 'GET' not in self._valid_methods:
            raise LibreNMSInvalidEndpointException("{} Endpoint doesnt accept GET command".format(self._endpoint_name))

        url = self._create_url([self._base_url, self._endpoint_name])
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
                LibreNMSEndpoint(
                    "{}/{}".format(self._endpoint_name, json_object[id_keyname]),
                    self._access_token,
                    self._base_url,
                    json_object
                )
            )

        return endpoint_objects

    def get(self, object_name):
        if 'GET' not in self._valid_methods:
            raise LibreNMSInvalidEndpointException("{} Endpoint doesnt accept GET command".format(self._endpoint_name))

        url = self._create_url([self._base_url, self._endpoint_name, object_name])
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
        return LibreNMSEndpoint(
            "{}/{}".format(self._endpoint_name, object_name),
            self._access_token,
            self._base_url,
            data=json_object
        )

    def delete(self, object_name):
        if 'DELETE' not in self._valid_methods:
            raise LibreNMSInvalidEndpointException("{} Endpoint doesnt accept DELETE command".format(self._endpoint_name))

        url = self._create_url([self._base_url, self._endpoint_name, object_name])
        response = requests.delete(
            url,
            headers=self._default_headers
        )

        if not self._valid_response(response):
            raise LibreNMSStatusNotOKException("An error occurred while fetching endpoints")

        return json.loads(response.text)

    def create(self, data):
        if 'POST' not in self._valid_methods:
            raise LibreNMSInvalidEndpointException("{} Endpoint doesnt accept POST command".format(self._endpoint_name))

        url = self._create_url([self._base_url, self._endpoint_name])
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
            super(LibreNMSEndpoint, self).__setattr__(key, value)
        else:
            self._endpoint_data[key] = value

    def __getattr__(self, attribute_name):
        if attribute_name in self._endpoint_data.keys():
            return self._endpoint_data[attribute_name]
        else:
            return LibreNMSEndpoint(
                "{}/{}".format(self._endpoint_name, attribute_name),
                self._access_token,
                self._base_url
            )

    def __repr__(self):
        return json.dumps(self._endpoint_data)


class LibreNMSAPI:
    def __init__(self, access_token, base_url):
        self._access_token = access_token
        self._base_url = base_url

    def __getattr__(self, attribute_name):
        return LibreNMSEndpoint(attribute_name, self._access_token, self._base_url)


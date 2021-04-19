import requests
import json
import logging
import os

api_rest = {"addRule": "api/firewall/filter/addRule",
            "searchDescription": "api/firewall/filter/searchRule?current=1&rowCount=20&searchPhrase=",
            "apply": "api/firewall/filter/apply/",
            "deleteRule": "api/firewall/filter/delRule",
            "getRule": "api/firewall/filter/getRule"
            }

class OPNsenseGW:

    def __init__(self, firewall_ip, api_key, api_secret, timeout=10, port="80", protocol="http"):
        self.remote_base_uri = f"{protocol}://{firewall_ip}"
        self.api_key = api_key
        self.api_secret = api_secret
        self.timeout = timeout
        self.port = port
        self.protocol = protocol

    def check_is_credentials_set(self):
        """
        Check if firewall's credentials are set
        :param: None
        :return: True if they are set, False otherwise
        """

        if self.api_key is not None and self.api_secret is not None:
            logging.info("Credentials are set")
            return True
        else:
            logging.error("Credenziali are not set")
            return False

    def check_firewall_rule_exist(self, rule_description):

        """
        Check if firewall's credentials are set
        :param: rule_description
        :return: True if the rule exist, False otherwise
        """

        if self.check_is_credentials_set():
            try:
                uri_path = os.path.join(self.remote_base_uri, api_rest.get("searchDescription"))
                r = requests.get(
                    f"{uri_path}{rule_description}",
                    auth=(self.api_key, self.api_secret), verify=False
                )
                if json.loads(r.text)['rowCount'] != 0:
                    return False
                else:
                    return True

            except requests.exceptions.RequestException as err:
                print("Ops: Something Else", err)
            except requests.exceptions.HTTPError as errh:
                print("Http Error:", errh)
            except requests.exceptions.ConnectionError as errc:
                print("Error Connecting:", errc)
            except requests.exceptions.Timeout as errt:
                print("Timeout Error:", errt)
        else:
            exit(0)

    def create_firewall_rule(self, rule_description, data):

        """
        Send add rule request to Firewall
        :param: rule_description
        :param: data
        :return: HTTP Status Code
        """

        # if self.check_firewall_rule_exist(rule_description):
        try:
            uri_path = os.path.join(self.remote_base_uri, api_rest.get("addRule"))
            r = requests.post(uri_path, auth=(self.api_key, self.api_secret), verify=False, json=data)
            return r
        except requests.exceptions.RequestException as err:
            print("OOps: Something Else", err)
        except requests.exceptions.HTTPError as errh:
            print("Http Error:", errh)
        except requests.exceptions.ConnectionError as errc:
            print("Error Connecting:", errc)
        except requests.exceptions.Timeout as errt:
            print("Timeout Error:", errt)
        # else:
        #     print("Rule alredy exist")

    def apply_firewall_rule(self):

        """
        Apply rule request to Firewall
        :param: None
        :return: HTTP Status Code
        """

        if self.check_is_credentials_set():
            try:
                r = None
                uri_path = os.path.join(self.remote_base_uri, api_rest.get("apply"))
                r = requests.post(uri_path, auth=(self.api_key, self.api_secret), verify=False)
            except requests.exceptions.RequestException as err:
                print("OOps: Something Else", err)
            except requests.exceptions.HTTPError as errh:
                print("Http Error:", errh)
            except requests.exceptions.ConnectionError as errc:
                print("Error Connecting:", errc)
            except requests.exceptions.Timeout as errt:
                print("Timeout Error:", errt)
            finally:
                return r

    def delete_firewall_rule(self, data, description): # da finire

        """
        Send add rule request to Firewall
        :param: rule_description
        :param: data
        :return: HTTP Status Code
        """

        # if not(self.check_firewall_rule_exist(description)):
        try:
            uri_path = os.path.join(self.remote_base_uri, api_rest.get("deleteRule"))
            final_url = f"{uri_path}/{data['rule']['uuid']}"
            r = requests.post(final_url, auth=(self.api_key, self.api_secret), verify=False)
            return r
        except requests.exceptions.RequestException as err:
            print("OOps: Something Else", err)
        except requests.exceptions.HTTPError as errh:
            print("Http Error:", errh)
        except requests.exceptions.ConnectionError as errc:
            print("Error Connecting:", errc)
        except requests.exceptions.Timeout as errt:
            print("Timeout Error:", errt)
        # else:
        #     print("Rule does not exist")

    def get_single_rule(self, uuid):
        if self.check_is_credentials_set():
            try:
                uri_path = os.path.join(self.remote_base_uri, api_rest.get("getRule"))
                r = requests.get(
                    f"{uri_path}/{uuid}",
                    auth=(self.api_key, self.api_secret), verify=False
                )
                # print(json.loads(r.text))
                return json.loads(r.text)

            except requests.exceptions.RequestException as err:
                print("Ops: Something Else", err)
            except requests.exceptions.HTTPError as errh:
                print("Http Error:", errh)
            except requests.exceptions.ConnectionError as errc:
                print("Error Connecting:", errc)
            except requests.exceptions.Timeout as errt:
                print("Timeout Error:", errt)
        else:
            exit(0)

    def get_all_firewall_rules(self):

        """
        Check if firewall's credentials are set
        :param: rule_description
        :return: True if the rule exist, False otherwise
        """

        if self.check_is_credentials_set():
            try:
                uri_path = os.path.join(self.remote_base_uri, api_rest.get("searchDescription"))
                r = requests.get(
                    f"{uri_path}",
                    auth=(self.api_key, self.api_secret), verify=False
                )
                if json.loads(r.text)['rowCount'] != 0:
                    return json.loads(r.text)['rows']
                else:
                    return False

            except requests.exceptions.RequestException as err:
                print("Ops: Something Else", err)
            except requests.exceptions.HTTPError as errh:
                print("Http Error:", errh)
            except requests.exceptions.ConnectionError as errc:
                print("Error Connecting:", errc)
            except requests.exceptions.Timeout as errt:
                print("Timeout Error:", errt)
        else:
            exit(0)
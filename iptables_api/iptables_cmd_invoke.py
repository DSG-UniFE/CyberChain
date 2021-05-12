import os
import time
import json
import socket
import requests
import threading

import pandas as pd
from configparser import ConfigParser

start_global = 0.0
api_invoke_add = []
api_invoke_delete = []
rule_apply = []
total_time = []
global_time = []
type_test = []


def change_format_float_list(old_list):
    new_list = list()
    for flt in old_list:
        new_list.append(str(flt).replace('.', ','))

    return new_list

def check_port_connection(host, port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.05)
        s.connect((host, int(port)))
        s.shutdown(socket.SHUT_RDWR)
        return True

    except:
        return False


def take_time(destination_net, action):
    global start_global
    global rule_apply
    global global_time

    # accept case
    response = False
    escape = True

    if action == 'DROP':
        print("in DROP")
        response = not response
        escape = not escape

    start_apply = time.monotonic()

    while response != escape:
        response = check_port_connection(destination_net[:-3], 80)

    end_apply = time.monotonic()
    print(f"Wait_apply_rule_any: start {start_apply} - end {end_apply} Time: {end_apply - start_apply}")
    print(f"Global_time_rule_any: start {start_global} - end {end_apply} Time: {end_apply - start_global}")
    rule_apply.append(end_apply - start_apply)
    global_time.append(end_apply - start_global)


def add_rule(uri_path, action, source_net, destination_net, protocol, saveTime=False):
    global start_global
    global api_invoke_add
    global type_test

    data = dict(rule=dict(src=source_net, table="FORWARD", protocol=protocol,
                          dst=destination_net, action=action, extra_flag="--destination-port 80"))

    start_send = time.monotonic()

    try:
        r = requests.post(uri_path, verify=False, json=data['rule'])
        if r.status_code == 201:
            end_send = time.monotonic()
            print(f"Add_rule: start {start_send} - end {end_send} Time: {end_send - start_send}")
            if saveTime:
                api_invoke_add.append(end_send - start_send)
        else:
            print("Issues with rule entry\n")
            response = json.loads(r.text)
            print(response)
            exit(1)

    except requests.exceptions.RequestException as err:
        print("Ops: Something Else", err)
        print("Server non attivo")
        exit(3)

    except requests.exceptions.HTTPError as errh:
        print("Http Error:", errh)

    except requests.exceptions.ConnectionError as errc:
        print("Error Connecting:", errc)

    except requests.exceptions.Timeout as errt:
        print("Timeout Error:", errt)


def delete_rule(uri_path, saveTime=False):
    global start_global
    global api_invoke_add
    global type_test

    data = dict(delete="delete")
    start_send = time.monotonic()
    r = None
    try:
        r = requests.post(uri_path, verify=False, json=data['delete'])
        if r.status_code == 201:
            end_send = time.monotonic()
            print(f"Delete rule."
                  f"Time: {end_send - start_send}")
            if saveTime:
                api_invoke_delete.append(end_send - start_send)
        else:
            print("Issues with rule entry\n")
            exit(1)

    except requests.exceptions.RequestException as err:
        print("Ops: Something Else", err)
        print("Server non attivo")
        exit(3)

    except requests.exceptions.HTTPError as errh:
        print("Http Error:", errh)

    except requests.exceptions.ConnectionError as errc:
        print("Error Connecting:", errc)

    except requests.exceptions.Timeout as errt:
        print("Timeout Error:", errt)


def add_rule_and_take_application_time(uri_path, source_net, destination_net, protocol, action, saveTime=False):
    threading.Thread(target=add_rule(uri_path=uri_path, action=action, source_net=source_net,
                                     destination_net=destination_net, protocol=protocol, saveTime=saveTime)).start()

    threading.Thread(target=take_time(destination_net, action)).start()


def print_test_port_80_results():

    df = pd.DataFrame(
        {
            "API Invoke delete": change_format_float_list(api_invoke_delete),
            "API Invoke Add": change_format_float_list(api_invoke_add),
            "Rule apply": change_format_float_list(rule_apply),
            "Total Time": change_format_float_list(total_time),
            "Global Time": change_format_float_list(global_time)
        }
    )

    print(df)
    return df


def execute_test(remote_base_uri, source_net, destination_net, protocol):
    global start_global

    iptables_api_add = "add/rule"
    uri_path_add = os.path.join(remote_base_uri, iptables_api_add)

    iptables_api_delete = "delete/rule"
    uri_path_delete = os.path.join(remote_base_uri, iptables_api_delete)

    start_send = time.monotonic()
    start_global = start_send
    print(start_global)
    delete_rule(uri_path_delete, True)
    print(f"Eliminated the rule that blocks IP on port 80")
    add_rule_and_take_application_time(uri_path_add, source_net, destination_net, protocol=protocol, action='ACCEPT', saveTime=True)
    print("Add accept rule destination IP on port 80")


def calculate_total_time(i):
    global api_invoke_add
    global api_invoke_delete
    global rule_apply
    global total_time

    total_time.append(api_invoke_add[i] + api_invoke_delete[i] + rule_apply[i])
    print(total_time)


def remove_all_rules(remote_base_uri):
    iptables_api_delete = "delete/rule"
    uri_path_delete = os.path.join(remote_base_uri, iptables_api_delete)
    for _ in range(2):
        delete_rule(uri_path_delete)


if __name__ == '__main__':
    # Read configuration file
    configuration = ConfigParser()
    abs_folder_path = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    configuration.read(os.path.join(abs_folder_path, 'configuration.ini'))

    # Parameters
    protocol = configuration['IPTABLES']['protocol']
    port = configuration['IPTABLES']['port']
    gateway_address = configuration['IPTABLES']['gateway_address']
    remote_base_uri = f"{protocol}://{gateway_address}:{port}"
    source_net = configuration['IPTABLES']['source_net']
    destination_net = configuration['IPTABLES']['destination_net']
    n_rules = int(configuration['IPTABLES']['n_rules'])

    iptables_api_add = "add/rule"
    uri_path_add = os.path.join(remote_base_uri, iptables_api_add)

    for i in range(n_rules):
        remove_all_rules(remote_base_uri)
        time.sleep(4)

        add_rule(uri_path=uri_path_add, action='DROP', source_net=source_net,
                 destination_net=destination_net, protocol='tcp')
        time.sleep(4)

        add_rule(uri_path=uri_path_add, action='DROP', source_net=source_net,
                 destination_net=destination_net, protocol='tcp')
        time.sleep(4)
        execute_test(remote_base_uri, source_net, destination_net, 'tcp')
        time.sleep(4)

        calculate_total_time(i)
        time.sleep(4)

    df = print_test_port_80_results()
    df.to_csv(os.path.join(os.path.dirname(abs_folder_path), 'iptables.csv'), sep=';', index=False)

import json
import os
import threading
import time
from datetime import datetime
import requests
import pandas as pd
import socket

start_global = 0.0
api_invoke_add = []
api_invoke_delete = []
rule_apply = []
total_time = []
global_time = []
type_test = []


def check_port_connection(host, port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.05)
        s.connect((host, int(port)))
        s.shutdown(socket.SHUT_RDWR)
        return True
    except:
        return False


def take_time(type, destination):
    global start_global
    global rule_apply
    global global_time
    start_apply = time.monotonic()

    print(type)
    if type == "BL":
        response = 0
        escape = 31744
    else:
        response = 1
        escape = 0

    while response != escape:
        response = os.system(f"timeout 0.05 ping -c 1 {destination[:-3]}  >/dev/null")
        # print(response)
        # time.sleep(0.25)

    end_apply = time.monotonic()
    print(f"Wait_apply_rule_any: start {start_apply} - end {end_apply} Time: {end_apply - start_apply}")
    print(f"Global_time_rule_any: start {start_global} - end {end_apply} Time: {end_apply - start_global}")
    rule_apply.append(end_apply - start_apply)
    global_time.append(end_apply - start_global)


def take_time_telnet(type, destination):
    global start_global
    global rule_apply
    global global_time
    start_apply = time.monotonic()

    if type == "BL":
        response = True
        escape = False
    else:
        response = False
        escape = True
    while response != escape:
        response = check_port_connection(destination[:-3], 80)
        # time.sleep(0.25)

    end_apply = time.monotonic()
    print(f"Wait_apply_rule_any: start {start_apply} - end {end_apply} Time: {end_apply - start_apply}")
    print(f"Global_time_rule_any: start {start_global} - end {end_apply} Time: {end_apply - start_global}")
    rule_apply.append(end_apply - start_apply)
    global_time.append(end_apply - start_global)


def add_rule(uri_path, action, source_net, destination_net, protocol, test_port_80=False, time_calulation=True):
    global start_global
    global api_invoke_add
    global type_test

    type_test.append(action)

    # sudo iptables -I FORWARD -s 192.168.51.51 -d 192.168.50.50 -p icmp --icmp-type echo-request -j ACCEPT/DROP
    if protocol == 'icmp':
        data = dict(rule=dict(src=source_net, table="FORWARD", protocol="icmp",
                              dst=destination_net, action=action, extra_flag="--icmp-type echo-request"))
    else:
        data = dict(rule=dict(src=source_net, table="FORWARD", protocol="tcp",
                              dst=destination_net, action=action, extra_flag="--destination-port 80"))


    start_send = time.monotonic()
    if not test_port_80:
        start_global = start_send
    r = None
    try:
        r = requests.post(uri_path, verify=False, json=data['rule'])
        if r.status_code == 201:
            end_send = time.monotonic()
            response = json.loads(r.text)
            print(f"Add_rule: start {start_send} - end {end_send} Time: {end_send - start_send}")
            if time_calulation:
                api_invoke_add.append(end_send - start_send)
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


def delete_rule_ping(uri_path, time_calulation=True):
    global start_global
    global api_invoke_add
    global type_test


    data = dict(delete="delete")
    start_send = time.monotonic()
    r = None
    try:
        r = requests.post(uri_path, verify=False, json=data['delete'])
        # print(json.loads(r.text))
        if r.status_code == 201:
            end_send = time.monotonic()
            print(f"Delete rule."
                  f"Time: {end_send - start_send}")
            if time_calulation:
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


def wl_bl_add_alternate(uri_path, source_net, destination_net, n_loop, current_type_ping_test,
                        test_port_80=False, protocol='icmp'):
    action = None
    current_type_ping_test = current_type_ping_test
    next_type_ping_test = None

    for _ in range(n_loop):
        if current_type_ping_test == 'WL':
            action = "DROP"
            next_type_ping_test = 'BL'
        elif current_type_ping_test == 'BL':
            action = "ACCEPT"
            next_type_ping_test = 'WL'
        else:
            print("Indicate test mode")
            exit(30)


        threading.Thread(target=add_rule(uri_path=uri_path, action=action, source_net=source_net,
                                         destination_net=destination_net, protocol=protocol,
                                         test_port_80=test_port_80)).start()

        if protocol == 'icmp':
            threading.Thread(target=take_time(next_type_ping_test, destination_net)).start()
        else:
            threading.Thread(target=take_time_telnet(next_type_ping_test, destination_net)).start()

        # time.sleep(4)
        current_type_ping_test = next_type_ping_test


def print_test_port_80_results():

    print(len(api_invoke_delete))
    print(len(api_invoke_add))
    print(len(rule_apply))
    print(len(total_time))
    print(len(global_time))

    df = pd.DataFrame(
        {
            "API Invoke delete": api_invoke_delete,
            "API Invoke Add": api_invoke_add,
            "Rule apply": rule_apply,
            "Total Time": total_time,
            "Global Time": global_time
        }
    )

    print(df)
    return df

def test_port_80(remote_base_uri, source_net, destination_net):
    global start_global
    # prepatazione ambiente

    iptables_api_add = "add/rule"
    uri_path_add = os.path.join(remote_base_uri, iptables_api_add)

    iptables_api_delete = "delete/rule"
    uri_path_delete = os.path.join(remote_base_uri, iptables_api_delete)

    start_send = time.monotonic()
    start_global = start_send
    print(start_global)
    delete_rule_ping(uri_path_delete)
    print(f"Eliminata la regola che blocca ip su porta 80")
    wl_bl_add_alternate(uri_path_add, source_net, destination_net, 1, 'BL', test_port_80=True, protocol='telnet')
    print(f"Aggiunta regola permetti ip di destinazione su porta 80")


def calculate_total_time(i):
    global api_invoke_add
    global api_invoke_delete
    global rule_apply
    global total_time

    total_time.append(api_invoke_add[i] + api_invoke_delete[i] + rule_apply[i])
    print(total_time)


if __name__ == '__main__':
    protocol = "http"
    port = "5000"
    remote_base_uri = f"{protocol}://<gateway address>:{port}"
    source_net = "<source address>/24"
    destination_net = "<destination address>/24"
    n_rules = 6

    iptables_api_add = "add/rule"
    uri_path_add = os.path.join(remote_base_uri, iptables_api_add)

    iptables_api_delete = "delete/rule"
    uri_path_delete = os.path.join(remote_base_uri, iptables_api_delete)

    # uri_path_add = os.path.join(remote_base_uri, iptables_api_add)
    # wl_bl_add_alternate(uri_path_add, source_net, destination_net, n_rules, 'WL', test_port_80=False, protocol='telnet')
    iptables_api_add = "add/rule"
    uri_path_add = os.path.join(remote_base_uri, iptables_api_add)
    for i in range(10):
        add_rule(uri_path=uri_path_add, action='DROP', source_net=source_net,
                 destination_net=destination_net, protocol=protocol,
                 test_port_80=True, time_calulation=False)

        print(f"Aggiunta regola tutto negato")

        add_rule(uri_path=uri_path_add, action='DROP', source_net=source_net,
                 destination_net=destination_net, protocol=protocol,
                 test_port_80=True, time_calulation=False)
        time.sleep(4)
        test_port_80(remote_base_uri, source_net, destination_net)
        time.sleep(4)
        calculate_total_time(i)
        delete_rule_ping(uri_path_delete, False)
        delete_rule_ping(uri_path_delete, False)
        time.sleep(4)

    df = print_test_port_80_results()
    df.to_csv('./iptables.csv', index=False)

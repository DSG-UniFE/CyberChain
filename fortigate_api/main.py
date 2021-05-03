import os
import time
import socket
import threading

import pandas as pd
from configparser import ConfigParser

import pyfortiapimod


start_global = 0.0
api_invoke_add = []
api_invoke_move = []
rule_apply = []
global_time = []
total_time = []
api_invoke_delete = []


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

    if action == 'deny':
        print("in deny")
        response = not response
        escape = not escape

    start_apply = time.monotonic()

    while response != escape:
        response = check_port_connection(destination_net[:-3], 80)
        # print(response)
        # time.sleep(0.25)

    end_apply = time.monotonic()
    print(f"Wait_apply_rule: start {start_apply} - end {end_apply} Time: {end_apply - start_apply}")
    print(f"Global_time_rule: start {start_global} - end {end_apply} Time: {end_apply - start_global}")
    rule_apply.append(end_apply - start_apply)
    global_time.append(end_apply - start_global)


def get_policy_rules(fgt):
    print("List of entered rules:")
    rules = fgt.get_firewall_policy()
    return rules


def remove_rule(fgt, id, takeStartTime=True):
    global api_invoke_delete
    policy_id = id
    start_delete = time.monotonic()
    reply = fgt.delete_firewall_policy(policy_id)  # creo la rule
    if reply == 200:
        end_delete = time.monotonic()
        if takeStartTime:
            api_invoke_delete.append(end_delete - start_delete)
        print(f"The rule with ID {policy_id} has been deleted in {end_delete - start_delete} seconds")
    else:
        print("Problems with rule deletion")


def remove_all_rules(fgt):
    rules = get_policy_rules(fgt)
    if rules != 404:
        for i in range(len(rules)):
            remove_rule(fgt, i + 1, False)
        print("All rule are deleted")
    else:
        print("No rules")


def add_rule(fgt, data, takeStartTime=True, time_calulation=True):
    global start_global
    global api_invoke_add
    global api_invoke_move

    start_add = time.monotonic()
    if takeStartTime:
        start_global = start_add

    reply = fgt.create_firewall_policy(data['policyid'], data)
    if reply == 200:
        end = time.monotonic()
        if time_calulation:
            api_invoke_add.append(end - start_add)

        print(f"The rule with ID {data['policyid']} has been inserted in {end - start_add} seconds")

        if data['policyid'] == 1:
            print("First Rule")
        else:
            start_move = time.monotonic()
            fgt.move_rule(data['policyid'], "before", data['policyid'] - 1)
            end_move = time.monotonic()
            if time_calulation:
                api_invoke_move.append(end_move - start_move)
            print(f"The rule with ID {data['policyid']} has been moved in {end_move - start_move} seconds")

    else:
        print("Problems with rule insertion")
        print(reply)
        fgt.logout()
        exit(1)


def execute_test(fgt, source_name, destination_name, destination_net):
    global start_global
    start_send = time.monotonic()
    start_global = start_send
    print(f"Start global time test {start_global}")
    remove_rule(fgt, 1)
    print(f"Eliminated the rule that blocks IP on port 80")
    data = get_rule_data(1, 'Accept hostb -> hosta port 80', source_name, destination_name, 'accept')
    add_rule_and_take_application_time(fgt, data, destination_net, takeStartTime=False)
    print("Add accept rule destination IP on port 80")


def get_rule_data(policy_id, rule_name, source_name, destination_name, action):
    data = {
        'policyid': policy_id,
        'name': rule_name,
        'srcintf': [{'name': 'port1'}],  # è l'interfaccia collegata con il client
        'dstintf': [{'name': 'port2'}],  # è l'interfaccia collegata ad internet
        'srcaddr': [{'name': source_name}],
        'dstaddr': [{'name': destination_name}],
        'action': action,  # accept o deny
        'status': 'enable',
        'schedule': 'always',  # si possono inserire i giorni della settimana
        'service': [{'name': 'NGINX'}],  # servizi PING, HTTP, ecc.
        'nat': 'disable',
        'logtraffic': 'all'
    }

    return data


def add_rule_and_take_application_time(fgt, data, destination_net, takeStartTime=True):

    threading.Thread(target=add_rule(fgt, data, takeStartTime)).start()
    threading.Thread(target=take_time(destination_net, data['action'])).start()


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


def calculate_total_time(i):
    global api_invoke_add
    global api_invoke_delete
    global rule_apply
    global total_time

    total_time.append(api_invoke_add[i] + api_invoke_delete[i] + rule_apply[i])


if __name__ == '__main__':
    # Read configuration file
    configuration = ConfigParser()
    abs_folder_path = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    configuration.read(os.path.join(abs_folder_path, 'configuration.ini'))

    username = configuration['FORTIGATE']['username']
    password = configuration['FORTIGATE']['password']
    firewall_IP = configuration['FORTIGATE']['firewall_IP']
    source_name = configuration['FORTIGATE']['source_name']
    destination_name = configuration['FORTIGATE']['destination_name']
    destination_net = configuration['FORTIGATE']['destination_net']
    n_rules = int(configuration['FORTIGATE']['n_rules'])

    fgt = pyfortiapimod.FortiGate(ipaddr=firewall_IP, username=username, password=password, port='80')
    fgt.login()
    for i in range(n_rules):
        remove_all_rules(fgt)
        time.sleep(4)

        # Preparazione ambiente
        print("Add block rule destination ip on port 80")
        data = get_rule_data(1, "Block hostb -> hosta port 80", source_name, destination_name, 'deny')
        add_rule(fgt, data, takeStartTime=False, time_calulation=False)
        time.sleep(4)
        execute_test(fgt, source_name, destination_name, destination_net)
        calculate_total_time(i)
        time.sleep(4)

    df = print_test_port_80_results()
    df.to_csv(os.path.join(os.path.dirname(abs_folder_path), 'fortigate.csv'), index=False)
    fgt.logout()

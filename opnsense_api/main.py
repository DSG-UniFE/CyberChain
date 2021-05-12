import os
import json
import time
import utils
import threading

import pandas as pd
from configparser import ConfigParser

from opnsenseapi import OPNsenseGW

start_global = 0.0
api_invoke_add = []
api_invoke_delete = []
api_invoke_apply = []
rule_apply = []
total_time = []
global_time = []
uri_rules_added = []


def take_time(destination_net, action):
    global start_global
    global rule_apply
    global global_time

    # accept case
    response = False
    escape = True

    if action == 'block':
        print("in block")
        response = not response
        escape = not escape

    start_apply = time.monotonic()

    while response != escape:
        response = utils.check_port_connection(destination_net[:-3], 80)
        # print(response)
        # time.sleep(0.25)

    end_apply = time.monotonic()
    print(f"Wait_apply_rule_any: start {start_apply} - end {end_apply} Time: {end_apply - start_apply}")
    print(f"Global_time_rule_any: start {start_global} - end {end_apply} Time: {end_apply - start_global}")
    rule_apply.append(end_apply - start_apply)
    global_time.append(end_apply - start_global)


def add_rule(ops, data, takeStartTime=False, saveTime=False):
    global start_global
    global api_invoke_add
    global api_invoke_apply
    global uri_rules_added

    start_send = time.monotonic()
    if takeStartTime:
        start_global = start_send

    r = ops.create_firewall_rule(data)
    response = json.loads(r.text)
    if r.status_code == 200:
        uri_rules_added.append(response['uuid'])
        uri_rules_added.reverse()
        end_send = time.monotonic()
        print(
            f"The rule with description {data['rule']['description']} has been inserted in {end_send - start_send} seconds")
        if saveTime:
            api_invoke_add.append(end_send - start_send)
        start_apply = time.monotonic()
        ops.apply_firewall_rule()
        stop_apply = time.monotonic()
        print(f"Apply rule executed: start {start_apply} - end {stop_apply} Time: {stop_apply - start_apply}")
        if saveTime:
            api_invoke_apply.append(stop_apply - start_apply)
    else:
        response = json.loads(r.text)
        print(f"Issues with rule entry {response}")
        exit(1)


def delete_rule_no_apply(ops, uuid, description, time_calculation=True):
    global start_global
    global api_invoke_delete
    global api_invoke_apply_delete

    data = dict(rule=dict(uuid=uuid))
    start_send = time.monotonic()
    r = None
    r = ops.delete_firewall_rule(data, description)
    if r is None:
        print("Issues with rule entry\n")
        exit(1)
    elif r.status_code == 200:
        end_send = time.monotonic()
        response = json.loads(r.text)
        print(f"Tempo invio richiesta eliminazione {end_send - start_send}")
        if time_calculation:
            api_invoke_delete.append(end_send - start_send)
        if len(response) > 0:
            pass
        else:
            print("rule %s not found" % description)


def remove_rule(ops, uuid, description, saveTime=False):
    global start_global
    global api_invoke_delete

    data = {
        'rule': {
            'uuid': uuid,
        }
    }

    start_delete = time.monotonic()

    r = ops.delete_firewall_rule(data)

    if r.status_code == 200:
        end_delete = time.monotonic()
        print(f"The rule with description {uuid} has been deleted in {end_delete - start_delete} seconds")
        if saveTime:
            api_invoke_delete.append(end_delete - start_delete)
    else:
        response = json.loads(r.text)
        print(f"Issues with rule deleting {response}")
        exit(1)


def print_test_port_80_results():

    df = pd.DataFrame(
        {
            "API Invoke delete": utils.change_format_float_list(api_invoke_delete),
            "API Invoke Add": utils.change_format_float_list(api_invoke_add),
            "API Invoke apply": utils.change_format_float_list(api_invoke_apply),
            "Rule apply": utils.change_format_float_list(rule_apply),
            "Total Time:": utils.change_format_float_list(total_time),
            "Global Time": utils.change_format_float_list(global_time)
        }
    )

    pd.set_option('display.max_columns', None)
    pd.set_option('display.max_colwidth', None)

    print(df)
    return df


def get_all_filtered_rules(ops):
    list_rules = ops.get_all_firewall_rules()
    if list_rules:
        return utils.extract_uuid_description(list_rules)
    else:
        return False


def remove_all_rules(ops):
    rules = get_all_filtered_rules(ops)
    if not rules:
        print("No rules")
    else:
        for rule in rules:
            remove_rule(ops, rule['uuid'], rule['description'], saveTime=False)
        ops.apply_firewall_rule()
        print("Deleted all rules")


def delete_single_rule_v2(ops, sequence, saveTime=False, ex_apply=True):
    global uri_rules_added
    if not uri_rules_added:
        print("No rules")
    else:
        remove_rule(ops, uri_rules_added[sequence-1], uri_rules_added[sequence-1], saveTime)
        uri_rules_added.remove(uri_rules_added[sequence-1])

    if ex_apply:
        ops.apply_firewall_rule()


def delete_single_rule(ops, sequence, saveTime=False, ex_apply=True):
    rules = get_all_filtered_rules(ops)
    print(rules)
    if not rules:
        print("No rules")
    else:
        remove_rule(ops, rules[sequence-1]['uuid'], rules[sequence-1]['description'], saveTime)

    if ex_apply:
        ops.apply_firewall_rule()


def get_complete_rules_info(ops):
    new_rules = []
    rules = get_all_filtered_rules(ops)
    for rule in rules:
        detailed_rule = ops.get_single_rule(rule['uuid'])
        selected = detailed_rule['rule']['action']['pass']['selected']
        if selected == 1:
            action = "pass"
        else:
            action = "block"

        new_rule = dict(uuid=rule['uuid'], description=rule['description'], action=action)
        new_rules.append(new_rule)
    return new_rules


def calculate_total_time(i):
    global api_invoke_add
    global api_invoke_delete
    global api_invoke_apply
    global rule_apply
    global total_time

    total_time.append(api_invoke_add[i] + api_invoke_delete[i] + api_invoke_apply[i] + rule_apply[i])
    print(total_time)


def add_rule_and_take_application_time(ops, data, destination_net, takeStartTime=False, saveTime=False):
    threading.Thread(target=add_rule(ops, data, takeStartTime, saveTime)).start()
    threading.Thread(target=take_time(destination_net, data['rule']['action'])).start()


def execute_test(ops, source_net, destination_net):
    global start_global
    start_send = time.monotonic()
    start_global = start_send
    print(f"Start global time test {start_global}")
    delete_single_rule_v2(ops, 1, saveTime=True, ex_apply=False)
    print(f"Eliminated the rule that blocks IP on port 80")
    data = get_rule_data("accept telnet service from host A to host B", 1, source_net, destination_net, 'pass',
                         'lan', 'TCP', '80')
    add_rule_and_take_application_time(ops, data, destination_net, takeStartTime=False, saveTime=True)
    print("Add accept rule destination IP on port 80")


def get_rule_data(rule_description, sequence, source_net, destination_net, action, interface, protocol,
                  destination_port):
    data = {
        'rule': {
            'description': rule_description,
            'sequence': sequence,
            'source_net': source_net,
            'protocol': protocol,
            'destination_net': destination_net,
            'action': action,  # accept o deny
            'interface': interface,
        }
    }

    if destination_net is not None:
        data['rule']['destination_port'] = destination_port

    return data


if __name__ == '__main__':
    # Read configuration file
    configuration = ConfigParser()
    abs_folder_path = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    configuration.read(os.path.join(abs_folder_path, 'configuration.ini'))

    # Parameters
    firewall_IP = configuration['OPNSENSE']['firewall_IP']
    ops = OPNsenseGW(firewall_IP, configuration['OPNSENSE']['api_key'], configuration['OPNSENSE']['api_secret'])
    source_net = configuration['OPNSENSE']['source_net']
    destination_net = configuration['OPNSENSE']['destination_net']
    n_rules = int(configuration['OPNSENSE']['n_rules'])
    ###################

    for i in range(n_rules):
        remove_all_rules(ops)
        uri_rules_added.clear()
        time.sleep(4)
        # Preparazione ambiente
        print("Add block all traffic rule - whitelist mode")
        data = get_rule_data("block all traffic", 2, source_net, destination_net, 'block',
                             'lan', 'any', None)
        add_rule(ops, data, takeStartTime=False, saveTime=False)
        time.sleep(4)

        print("Add block rule destination ip on port 80")
        data = get_rule_data("block telnet service from host A to host B", 1, source_net, destination_net, 'block',
                             'lan', 'TCP', '80')
        add_rule(ops, data, takeStartTime=False, saveTime=False)
        time.sleep(4)
        execute_test(ops, source_net, destination_net)
        calculate_total_time(i)
        time.sleep(4)

    df = print_test_port_80_results()
    df.to_csv(os.path.join(os.path.dirname(abs_folder_path), 'opnsense.csv'), sep=";", index=False)

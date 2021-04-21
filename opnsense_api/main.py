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
api_invoke_apply_delete = []  # non più utilizzato
rule_apply = []
total_time = []
global_time = []
type_test = []
uri_rule_added = []


def take_time_telnet(kind, destination_net):
    global start_global
    global rule_apply
    global global_time
    start_apply = time.monotonic()

    if kind == "BL":
        response = True
        escape = False
    else:
        response = False
        escape = True
    while response != escape:
        response = utils.check_port_connection(destination_net[:-3], 80)
        # time.sleep(0.25)

    end_apply = time.monotonic()
    print(f"Wait_apply_rule_any: start {start_apply} - end {end_apply} Time: {end_apply - start_apply}")
    print(f"Global_time_rule_any: start {start_global} - end {end_apply} Time: {end_apply - start_global}")
    rule_apply.append(end_apply - start_apply)
    global_time.append(end_apply - start_global)


def take_time(kind, destination_net):
    global start_global
    global rule_apply
    global global_time
    start_apply = time.monotonic()

    if kind == "BL":
        response = 0
        escape = 31744
    else:
        response = 1
        escape = 0

    while response != escape:
        response = os.system(f"timeout 0.05 ping -c 1 {destination_net[:-3]}  >/dev/null")
        print(response)
        # time.sleep(0.25)

    end_apply = time.monotonic()
    print(f"Wait_apply_rule_any: start {start_apply} - end {end_apply} Time: {end_apply - start_apply}")
    print(f"Global_time_rule_any: start {start_global} - end {end_apply} Time: {end_apply - start_global}")
    rule_apply.append(end_apply - start_apply)
    global_time.append(end_apply - start_global)


def add_rule_any(ops, action, source_net, destination_net, count=True, test_port_80=False, time_calculation=True):
    global start_global
    global api_invoke_add
    global api_invoke_apply
    global type_test

    type_test.append(action)
    # define the basics, hostname to use and description used to identify our test rule
    if isinstance(count, bool):
        rule_description = f"{action} any service from host A to host B"
        sequence = "1"
    else:
        rule_description = f"{action} any service from host A to host B {count}"
        sequence = count

    interface = "lan"  # must insert in lower case
    data = dict(rule=dict(description=rule_description,
                          sequence=sequence,
                          source_net=source_net,
                          protocol="any",
                          destination_net=destination_net,
                          action=action,
                          interface=interface,
                          # destination_port="80",
                          ))

    start_send = time.monotonic()
    if not test_port_80:
        start_global = start_send
    r = None
    r = ops.create_firewall_rule(rule_description, data)
    if r is None:
        print("Issues with rule entry\n")
        exit(1)
    elif r.status_code == 200:
        end_send = time.monotonic()
        response = json.loads(r.text)
        print(f"Add_rule_any: start {start_send} - end {start_send} Time: {end_send - start_send}")
        if time_calculation:
            api_invoke_add.append(end_send - start_send)
        if len(response) > 0:
            start_apply = time.monotonic()
            ops.apply_firewall_rule()
            stop_apply = time.monotonic()
            print(f"Apply_rule_any: start {start_apply} - end {stop_apply} Time: {stop_apply - start_apply}")
            if time_calculation:
                api_invoke_apply.append(stop_apply - start_apply)
        else:
            print("rule %s not found" % rule_description)


def add_rule_telnet(ops, action, source_net, destination_net, count=True, test_port_80=False, time_calculation=True):
    global start_global
    global api_invoke_add
    global api_invoke_apply
    global type_test

    type_test.append(action)
    # define the basics, hostname to use and description used to identify our test rule
    if isinstance(count, bool):
        rule_description = f"{action} telnet service from host A to host B"
        sequence = "1"
    else:
        rule_description = f"{action} telnet service from host A to host B {count}"
        sequence = count

    interface = "lan"  # must insert in lower case
    data = dict(rule=dict(description=rule_description,
                          sequence=sequence,
                          source_net=source_net,
                          protocol="TCP",
                          destination_net=destination_net,
                          action=action,
                          interface=interface,
                          destination_port="80",
                          ))

    start_send = time.monotonic()
    if not test_port_80:
        start_global = start_send
    r = None
    r = ops.create_firewall_rule(rule_description, data)
    if r is None:
        print("Issues with rule entry\n")
        exit(1)
    elif r.status_code == 200:
        end_send = time.monotonic()
        response = json.loads(r.text)
        print(f"Add_rule_any: start {start_send} - end {start_send} Time: {end_send - start_send}")
        if time_calculation:
            api_invoke_add.append(end_send - start_send)
        if len(response) > 0:
            start_apply = time.monotonic()
            ops.apply_firewall_rule()
            stop_apply = time.monotonic()
            print(f"Apply_rule_any: start {start_apply} - end {stop_apply} Time: {stop_apply - start_apply}")
            if time_calculation:
                api_invoke_apply.append(stop_apply - start_apply)
        else:
            print("rule %s not found" % rule_description)


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


def delete_rule(ops, uuid, description, time_calculation=True):
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
            start_apply = time.monotonic()
            ops.apply_firewall_rule()
            stop_apply = time.monotonic()
            print(f"Tempo applicazione eliminazione regola {stop_apply - start_apply}")
            if time_calculation:
                api_invoke_apply_delete.append(stop_apply - start_apply)
        else:
            print("rule %s not found" % description)


def wl_bl_add_alternate(ops, source_net, destination_net, n_loop, type_protocol, current_type_ping_test,
                        test_port_80=False):
    action = None
    current_type_ping_test = current_type_ping_test
    next_type_ping_test = None
    count = n_loop
    df = None

    for i in range(n_loop):
        print(f" ################### Regola {i + 1} ###################")
        if current_type_ping_test == 'WL':
            action = "block"
            next_type_ping_test = 'BL'
        elif current_type_ping_test == 'BL':
            action = "pass"
            next_type_ping_test = 'WL'
        else:
            print("Indicate test mode")
            exit(30)

        if type_protocol == "ping":
            threading.Thread(
                target=add_rule_any(ops, action=action, source_net=source_net, destination_net=destination_net,
                                    count=count)).start()
            threading.Thread(target=take_time(kind=next_type_ping_test, destination_net=destination_net)).start()
            time.sleep(4)
            current_type_ping_test = next_type_ping_test
            count = count - 1
        else:
            threading.Thread(
                target=add_rule_telnet(ops, action=action, source_net=source_net, destination_net=destination_net,
                                       count=count, test_port_80=test_port_80)).start()
            threading.Thread(target=take_time_telnet(kind=next_type_ping_test, destination_net=destination_net)).start()
            # time.sleep(4)
            current_type_ping_test = next_type_ping_test
            count = count - 1
        print(f" #######################################################")


def print_test_port_80_results():
    print(len(api_invoke_delete))
    print(len(api_invoke_add))
    print(len(api_invoke_apply))
    print(len(rule_apply))
    print(len(total_time))
    print(len(global_time))

    df = pd.DataFrame(
        {
            "API Invoke delete": api_invoke_delete,
            "API Invoke Add": api_invoke_add,
            "API Invoke apply": api_invoke_apply,
            "Rule apply": rule_apply,
            "Total Time:": total_time,
            "Global Time": global_time
        }
    )

    pd.set_option('display.max_columns', None)
    pd.set_option('display.max_colwidth', None)

    print(df)
    return df


def test_port_80(ops, source_net, destination_net):
    global start_global

    start_send = time.monotonic()
    start_global = start_send
    print(start_global)
    suppl_delete_single_rule_no_apply(ops, 0)
    print(f"Eliminata la regola che blocca ip su porta 80")
    wl_bl_add_alternate(ops, source_net, destination_net, 1, "telnet", "BL", test_port_80=True)
    print(f"Aggiunta regola permetti ip di destinazione su porta 80")


def suppl_get_all_filtered_rules(ops):
    list_rules = ops.get_all_firewall_rules()
    if list_rules:
        return utils.extract_uuid_description(list_rules)
    else:
        return False


def suppl_delete_all_rules(ops):
    rules = suppl_get_all_filtered_rules(ops)
    if not rules:
        print("No rules")
    else:
        for rule in rules:
            delete_rule(ops, rule['uuid'], rule['description'], time_calculation=False)
        print("Deleted all rules")


def suppl_delete_single_rule(ops, n, time_calculation=True):
    rules = suppl_get_all_filtered_rules(ops)
    print(rules)
    if not rules:
        print("No rules")
    else:
        delete_rule(ops, rules[n]['uuid'], rules[n]['description'], time_calculation)


def suppl_delete_single_rule_no_apply(ops, n, time_calculation=True):
    rules = suppl_get_all_filtered_rules(ops)
    print(rules)
    if not rules:
        print("No rules")
    else:
        delete_rule_no_apply(ops, rules[n]['uuid'], rules[n]['description'], time_calculation)


def suppl_get_complete_rules(ops):
    new_rules = []
    rules = suppl_get_all_filtered_rules(ops)
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


if __name__ == '__main__':
    # Read configuration file
    configuration = ConfigParser()
    configuration.read(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'configuration.ini'))

    # Parameters
    firewall_IP = configuration['OPNSENSE']['firewall_IP']
    ops = OPNsenseGW(firewall_IP, configuration['OPNSENSE']['api_key'], configuration['OPNSENSE']['api_secret'])
    source_net = configuration['OPNSENSE']['source_net']
    destination_net = configuration['OPNSENSE']['destination_net']
    n_rules = configuration['OPNSENSE']['n_rules']
    ###################
    # suppl_delete_all_rules(ops)

    # one shot WL with n_loop == 1
    # one shot BL with n_loop == 2 (WL+BL)
    # wl_bl_add_alternate(ops, source_net, destination_net, n_rules, "telnet", "WL")
    for i in range(10):
        add_rule_any(ops, action='block', source_net=source_net, destination_net=destination_net, count=2,
                     test_port_80=True, time_calculation=False)
        print(f"Aggiunta regola tutto negato")
        add_rule_telnet(ops, "block", source_net, destination_net, count=1, test_port_80=True, time_calculation=False)
        print(f"Aggiunta regola blocco ip di destinazione e su porta 80")
        time.sleep(4)
        test_port_80(ops, source_net, destination_net)
        time.sleep(4)
        suppl_delete_all_rules(ops)
        time.sleep(4)
        calculate_total_time(i)
        print_test_port_80_results()

    df = print_test_port_80_results()
    df.to_csv('./opnsense.csv', index=False)

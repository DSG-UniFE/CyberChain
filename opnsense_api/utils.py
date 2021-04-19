import socket


def extract_uuid_description(rule_objects):
    filtered_rules_list = []
    for obj in rule_objects:
        new_obj = dict(uuid=obj['uuid'], description=obj['description'])
        filtered_rules_list.append(new_obj)
    return filtered_rules_list


def check_port_connection(host, port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.05)
        s.connect((host, int(port)))
        s.shutdown(socket.SHUT_RDWR)
        return True
    except:
        return False

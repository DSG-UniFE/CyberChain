import flask
import subprocess
from flask import request, abort, jsonify

app = flask.Flask(__name__)


@app.route('/add/rule/icmp', methods=['POST'])
def add_rule():
    if not request.json or not 'action' in request.json:
        abort(400)
    else:
        new_rule = {'action': request.json.get('action'),
                    'src': request.json.get('src'),
                    'dst': request.json.get('dst'),
                    'protocol': request.json.get('protocol'),
                    'extra_flag': request.json.get('extra_flag'),
                    'table': 'FORWARD',
                    # 'if_in': request.json.get('if_in'),
                    # 'if_out': request.json.get('if_out')
                    }

        sudo_password = '<user password>'
        command = f"iptables -I {new_rule['table']} -s {new_rule['src']} -d "\
                  f"{new_rule['dst']} -j {new_rule['action']} -p {new_rule['protocol']} {new_rule['extra_flag']}"
        print(command)
        command = command.split()

        cmd1 = subprocess.Popen(['echo', sudo_password], stdout=subprocess.PIPE)
        cmd2 = subprocess.Popen(['sudo', '-S'] + command, stdin=cmd1.stdout, stdout=subprocess.PIPE)
        output = cmd2.stdout.read().decode()
        print(output)

        return jsonify({'rule': new_rule}), 201


@app.route('/delete/rule', methods=['POST'])
def delete_rule():
    if not request.json or not 'delete' in request.json:
        abort(400)
    else:
        sudo_password = 'hostgw'
        command = "iptables -D FORWARD 1"
        print(command)
        command = command.split()

        cmd1 = subprocess.Popen(['echo', sudo_password], stdout=subprocess.PIPE)
        cmd2 = subprocess.Popen(['sudo', '-S'] + command, stdin=cmd1.stdout, stdout=subprocess.PIPE)
        output = cmd2.stdout.read().decode()
        print(output)

        return jsonify({'Message': "Rule deleted"}), 201

if __name__ == '__main__':
    app.config["DEBUG"] = True
    app.run(host='0.0.0.0')

    # sudo iptables -I FORWARD -s 192.168.51.51 -d 192.168.50.50 -p icmp -j ACCEPT

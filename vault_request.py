#!/usr/bin/python3
# vault_request.py - Reading and updating Hashicorp Vault backends
# Author: Sjors101 <https://github.com/sjors101/>, 07/19/2018

import sys, requests, json, ast, textwrap


def print_help():
    print(textwrap.dedent("""\
    vault_request.py --host 127.0.0.1:8200 --token <token> --backend <secret backend> --mode <mode type>    
    EXAMPLE: vault_request.py --host 127.0.0.1:8200 --token '123456' --backend test --mode update --key backend.uri --value 'http://example.org'
    EXAMPLE: vault_request.py --host 127.0.0.1:8200 --token '123456' --backend test --mode print --key backend.uri
    
    --h         print this help
    --host      vault host with portnumber, example: 192.168.146.72:8200
    --token     token
    --backend   vault secret backend
    --key       key of value you want to change, required in mode overwrite and update
    --value     value you want to change, required in mode overwrite and update
    --mode      overwrite / update / print
    """))
    sys.exit()


def receive_input(argv):

    vault_host = ''
    vault_token = ''
    vault_backend = ''
    mode = ''
    key = ''
    value = ''

    for arg in range(len(argv)):
        if argv[arg] == '--h':
            print_help()
        if argv[arg] == '--host':
            vault_host = 'http://'+str(argv[arg+1])+'/v1/'
        if argv[arg] == '--token':
             vault_token = {'X-Vault-Token': argv[arg+1]}
        if argv[arg] == '--backend':
            vault_backend = argv[arg+1]
        if argv[arg] == '--mode':
            mode = argv[arg + 1]
        if argv[arg] == '--value':
            value = argv[arg+1]
        if argv[arg] == '--key':
            key = argv[arg + 1]

    vault_backend = vault_host + vault_backend

    if not vault_backend or not mode or not vault_host or not vault_token:
        print("Error, please provide more variables" + "\n")
        print_help()
    elif mode != "overwrite" and mode != "update" and mode != "print":
        print("Error, please provide correct mode" + "\n")
        print_help()
    elif mode == "print":
        vault_print(vault_backend, vault_token, key)
    elif mode == "update":
        if not key or not value:
            print("Error, please key and value" + "\n")
            print_help()
        else:
            vault_update(vault_backend, vault_token, key, value)
    elif mode == "overwrite":
        if not key or not value:
            print("Error, please key and value" + "\n")
            print_help()
        else:
            vault_overwrite(vault_backend, vault_token, key, value)
    else:
        print_help()


# READING FROM VAULT BACKEND
def vault_read(vault_backend, vault_token):
    read = requests.get(vault_backend, headers=vault_token, verify=False)

    if read.status_code == 404:
        print("ERROR, cant read backend, status_code:", read.status_code, 'backend:', vault_backend)
        exit()
    elif read.status_code == 403:
        print("ERROR, not authorized, status_code:", read.status_code)
        exit()
    else:
        vault_secrets = json.loads(read.text)
        vault_secrets = ast.literal_eval(json.dumps(vault_secrets['data']))
        return vault_secrets


# PRINTING
def vault_print(vault_backend, vault_token, key):
    vault_secrets = vault_read(vault_backend, vault_token)

    found_check = False

    if key:
        for vault_key, vault_value in vault_secrets.items():
            if str(vault_key) == str(key):
                print('-', vault_key, ':', vault_value)
                found_check = True
        if found_check is False:
            print("Value not found")
    elif not key:
        for vault_key, vault_value in vault_secrets.items():
            print('-', vault_key, ':', vault_value)


# UPDATING
def vault_update(vault_backend, vault_token, key, value):
    vault_secrets = vault_read(vault_backend, vault_token)

    update_check = False

    for vault_key, vault_value in vault_secrets.items():
        if str(vault_key) == str(key):
            print("-", str(vault_key), ':', str(vault_secrets[vault_key]))
            vault_secrets[vault_key] = value
            print("+", str(vault_key), ':', str(vault_secrets[vault_key]))
            update_check = True

    if update_check is True:
        requests.post(vault_backend, headers=vault_token, verify=False, json=vault_secrets)
        print("Vault updated")
    else:
        print("ERROR: key not found, updating nothing")


# OVERWRITE
def vault_overwrite(vault_backend, vault_token, key, value):
    vault_secrets = vault_read(vault_backend, vault_token)

    for vault_key, vault_value in vault_secrets.items():
        print("-", str(vault_key), ':', str(vault_secrets[vault_key]))

    vault_secrets = {str(key) : str(value)}
    print("+",str(key), ':', str(value))

    requests.post(vault_backend, headers=vault_token, verify=False, json=vault_secrets)
    print("Vault updated")


if __name__ == "__main__":
    receive_input(sys.argv[0:])

import sys
from subprocess import check_output, CalledProcessError
import deepsecurity
from deepsecurity.rest import ApiException
import requests


def download_file(url, file_name, timeout=5):
    print(f"Downloading {file_name}")

    with open(file_name, "w") as f:
        response = requests.get(url, timeout=timeout)
        f.write(response.text)


def get_rule_id(configuration, api_version, rule_type, rule_to_apply):
    if rule_type == "ips":
        rule_instance = deepsecurity.IntrusionPreventionRulesApi(deepsecurity.ApiClient(configuration))

    elif rule_type == "im":
        rule_instance = deepsecurity.IntegrityMonitoringRulesApi(deepsecurity.ApiClient(configuration))

    elif rule_type == "li":
        rule_instance = deepsecurity.LogInspectionRulesApi(deepsecurity.ApiClient(configuration))

    # Get the eicar rule id so we can assign it
    rule_id = 0
    try:
        if "ips" in rule_type:
            rule_response = rule_instance.list_intrusion_prevention_rules(api_version)
            attrs = rule_response._intrusion_prevention_rules
            rule_id = getid(attrs, rule_to_apply)
        if "im" in rule_type:
            rule_response = rule_instance.list_integrity_monitoring_rules(api_version)
            attrs = rule_response._integrity_monitoring_rules
            rule_id = getid(attrs, rule_to_apply)
        if "li" in rule_type:
            rule_response = rule_instance.list_log_inspection_rules(api_version)
            attrs = rule_response._log_inspection_rules
            rule_id = getid(attrs, rule_to_apply)

        return rule_id

    except ApiException as e:
        sys.exit(e)


def getid(attrs, rule_to_apply):
    ids = [len(attrs)]
    for x in attrs:
        if((getattr(x,"name") == rule_to_apply)):
            return(getattr(x,"id"))


def check_if_rule_assigned(rule_to_apply, rule_type, rule_id, policy_id, configuration, api_version, overrides):
    policy_instance = deepsecurity.PoliciesApi(deepsecurity.ApiClient(configuration))
    try:
        found = False
        policies = policy_instance.list_policies(api_version, overrides=overrides)
        for policy in policies.policies:
            if policy.id == policy_id:
                if("ips" in rule_type):
                    if (rule_id != 0) and (policy.intrusion_prevention.rule_ids is not None):
                        for policy_ids in policy.intrusion_prevention.rule_ids:
                            if policy_ids == rule_id:
                                print(rule_type + " rule \"" + rule_to_apply + " is already assigned")
                                found = True
                                break
                if("im" in rule_type):
                    if (rule_id != 0) and (policy.integrity_monitoring.rule_ids is not None):
                        for policy_ids in policy.integrity_monitoring.rule_ids:
                            if policy_ids == rule_id:
                                print(rule_type + " rule \"" + rule_to_apply + " is already assigned")
                                found = True
                                break
                if("li" in rule_type):
                    if (rule_id != 0) and (policy.log_inspection.rule_ids is not None):
                        for policy_ids in policy.log_inspection.rule_ids:
                            if policy_ids == rule_id:
                                print(rule_type + " rule \"" + rule_to_apply + " is already assigned")
                                found = True
                                break
                if(found == False):
                    #id_array=arr.array('I',policy.intrusion_prevention.rule_ids)
                    print(rule_type + " rule \"" + rule_to_apply + " was not assigned, need to assign it to the policy")
        return(found)
    except ApiException as e:
        print("An exception occurred when calling PoliciesApi.list_policies: %s\n" % e)


def get_last_im_scan(host_id, policy_id,configuration, api_version, overrides):
    try:
        computer_instance = deepsecurity.ComputersApi(deepsecurity.ApiClient(configuration))
        computers = computer_instance.list_computers(api_version, overrides=overrides)
        for computer in computers.computers:
            if(computer.policy_id == policy_id):
                if(computer.id == host_id):
                    return(computer.integrity_monitoring.last_integrity_scan)
    except ApiException as e:
        print("An exception occurred when calling ComputersApi.list_computers: %s\n" % e)


def getacstatus(host_id, policy_id,configuration, api_version, overrides):
    try:
        computer_instance = deepsecurity.ComputersApi(deepsecurity.ApiClient(configuration))
        computers = computer_instance.list_computers(api_version, overrides=overrides)
        for computer in computers.computers:
            if(computer.policy_id == policy_id):
                if(computer.id == host_id):
                    if(computer.tasks is not None):
                        print("Current status: " + computer.tasks.agent_tasks[0])
                        return(computer.tasks.agent_tasks[0])
                    else:
                        return(None)
    except ApiException as e:
        print("An exception occurred when calling ComputersApi.list_computers: %s\n" % e)


def getcomputerinfo(host_id, policy_id,configuration, api_version, overrides):
    try:
        computer_instance = deepsecurity.ComputersApi(deepsecurity.ApiClient(configuration))
        computers = computer_instance.list_computers(api_version, overrides=overrides)
        for computer in computers.computers:
            if(computer.policy_id == policy_id):
                if(computer.id == host_id):
                    print(computer)
    except ApiException as e:
        print("An exception occurred when calling ComputersApi.list_computers: %s\n" % e)


def run_command(cmd):
    print("Running command: " + cmd)
    split_cmd = cmd.split()

    try:
        output = check_output(split_cmd).decode('utf-8')
        print(f'Output: {output}')

    except CalledProcessError as e:
        sys.exit(f'Error: {e}')


def send_heartbeat(user_os):
    if user_os == 'linux':
        cmd = "sudo /opt/ds_agent/dsa_control -m"

    elif user_os == 'windows':
        cmd = "\"C:\Program Files\Trend Micro\Deep Security Agent\dsa_control\" -m"

    run_command(cmd)

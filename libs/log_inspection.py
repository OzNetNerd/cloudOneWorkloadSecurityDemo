import deepsecurity
from deepsecurity.rest import ApiException
from libs.utils import get_rule_id, check_if_rule_assigned, run_command, send_heartbeat
import time

RULE_MAP = {
    'linux': "Unix - Syslog",
    'windows': "Microsoft Windows Events"
}


def log_inspection_attack(policy_id, configuration, api_version, overrides, user_os, **kwargs):
    rule_to_apply = RULE_MAP[user_os]

    print("---Running The Log Inspection Test---")
    #Get the LI Rule ID
    rule_id = get_rule_id(configuration, api_version, "li", rule_to_apply)
    found = check_if_rule_assigned(rule_to_apply, "li", rule_id, policy_id, configuration, api_version, overrides)

    # If the rule is not assigned, then assign it
    if not found:
        assign_li_rule(rule_id, policy_id, configuration, api_version, overrides, True)
    
    # Run the tests
    run_attack(user_os)

    # If the rule was not originally assigned, remove it to restore the state of the policy
    if not found:
        assign_li_rule(rule_id, policy_id, configuration, api_version, overrides, False)
    
    send_heartbeat(user_os)
    print("---Log Inspection Test Completed---")  


def assign_li_rule(rule_to_apply, rule_id, policy_id, configuration, api_version, add_rule):
    try:
        # Get the current list of rules from the policy
        policies_api = deepsecurity.PoliciesApi(deepsecurity.ApiClient(configuration))
        current_rules = policies_api.describe_policy(policy_id, api_version, overrides=False)
    
        if add_rule:
            print("Adding the " + rule_to_apply + " rule to the policy")
            if current_rules.log_inspection.rule_ids is None:
                current_rules.log_inspection.rule_ids = rule_id
        
            elif li_rule_id not in current_rules.log_inspection.rule_ids:
                current_rules.log_inspection.rule_ids.append(rule_id)
        else:
            print("Removing the " + rule_to_apply + " rule from the policy")
            current_rules.log_inspection.rule_ids.remove(rule_id)
        
        # Add the new and existing intrusion prevention rules to a policy
        log_inspection_policy_extension = deepsecurity.LogInspectionPolicyExtension()
        log_inspection_policy_extension.rule_ids = current_rules.log_inspection.rule_ids
        policy = deepsecurity.Policy()
        policy.log_inspection = log_inspection_policy_extension
    
        # Configure sending policy updates when the policy changes
        policy.auto_requires_update = "on"
    
        # Modify the policy on Deep Security Manager
        modified_policy = policies_api.modify_policy(policy_id, policy, api_version)
    except ApiException as e:
        print("An exception occurred when calling PolicyIntegrityMonitoringRuleAssignmentsRecommendationsApi.add_intrusion_prevention_rule_ids_to_policy: %s\n" % e)


def run_attack(user_os):
    # if("ubuntu" in user_os):
    #     #Run the test
    #     cmd = "sudo adduser --disabled-password --gecos \"\" hacker1"
    #     output = run_command(cmd)
    #     time.sleep(2)
    #     cmd = "sudo deluser hacker1"
    #     output = run_command(cmd)
    if user_os == 'linux':
        #Run the test
        cmd = "sudo adduser -m hacker1"
        output = run_command(cmd)
        time.sleep(2)
        cmd = "sudo userdel -f -r hacker1"
        output = run_command(cmd)
    elif user_os =='windows':
        #Run the test
        cmd = "net user hacker1 Temp12345! /add"
        output = run_command(cmd)
        time.sleep(2)
        cmd = "net user hacker1 /delete"
        output = run_command(cmd)
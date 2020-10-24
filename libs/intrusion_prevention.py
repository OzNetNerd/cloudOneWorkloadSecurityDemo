import subprocess
import deepsecurity
from deepsecurity.rest import ApiException
from libs.utils import get_rule_id, check_if_rule_assigned, send_heartbeat
import time


def ips_attack(policy_id, configuration, api_version, overrides, user_os, **kwargs):
    rule_to_apply = "Restrict Download Of EICAR Test File Over HTTP"

    print("---Running The Intrusion Prevention Test---")
    rule_id = get_rule_id(configuration, api_version, rule_type="ips", rule_to_apply=rule_to_apply)
    found = check_if_rule_assigned(rule_to_apply, "ips", rule_id, policy_id, configuration, api_version, overrides)

    if not found:
        assign_ips_rule(rule_to_apply, rule_id, policy_id, configuration, api_version, overrides, True)
        
    # Wait for the policy to be sent
    time.sleep(10)

    # Attempt to get the Eicar file
    run_attack()
    
    # If the rule was not originally assigned, unassign it to restore the original state
    if not found:
        assign_ips_rule(rule_to_apply, rule_id, policy_id, configuration, api_version, overrides, False)

    send_heartbeat(user_os)
    print("---Intrusion Prevention Test Complete---")


def assign_ips_rule(rule_to_apply, rule_id, policy_id, configuration, api_version, overrides, add_rule):
    try:
        # Get the current list of rules from the policy
        policies_api = deepsecurity.PoliciesApi(deepsecurity.ApiClient(configuration))
        current_rules = policies_api.describe_policy(policy_id, api_version, overrides=False)

        if(add_rule == True):
            print("Adding the " + rule_to_apply + " rule to the policy")
            # Add the rule_id if it doesn't already exist in current_rules
            if current_rules.intrusion_prevention.rule_ids is None:
                current_rules.intrusion_prevention.rule_ids = rule_id
        
            elif rule_id not in current_rules.intrusion_prevention.rule_ids:
                current_rules.intrusion_prevention.rule_ids.append(rule_id)
        else:
            print("Removing the " + rule_to_apply + " rule from the policy")
            current_rules.intrusion_prevention.rule_ids.remove(rule_id)
    
        # Add the new and existing intrusion prevention rules to a policy
        intrusion_prevention_policy_extension = deepsecurity.IntrusionPreventionPolicyExtension()
        intrusion_prevention_policy_extension.rule_ids = current_rules.intrusion_prevention.rule_ids
        policy = deepsecurity.Policy()
        policy.intrusion_prevention = intrusion_prevention_policy_extension
    
        # Configure sending policy updates when the policy changes
        policy.auto_requires_update = "on"
    
        # Modify the policy on Deep Security Manager
        modified_policy = policies_api.modify_policy(policy_id, policy, api_version)
    except ApiException as e:
        print("An exception occurred when calling PolicyIntrusionPreventionRuleAssignmentsRecommendationsApi.add_intrusion_prevention_rule_ids_to_policy: %s\n" % e)


def run_attack():
    print("Attempting to download the Eicar file")
    subprocess.call('curl http://malware.wicar.org/data/eicar.com'.split())

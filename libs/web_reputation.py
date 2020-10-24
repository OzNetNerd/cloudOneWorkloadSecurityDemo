import deepsecurity
import subprocess
import time
from libs.utils import send_heartbeat


def web_reputation_attack(policy_id, configuration, api_version, overrides, user_os, **kwargs):
    print("---Running The Web Reputation Test---")
    current_state = checkifwrson(policy_id, configuration, api_version, overrides)
    if ("off" in current_state):
        modifywrsstate(policy_id, configuration, api_version, overrides, "on")
    time.sleep(10)
    # Attempt to access each of the sites
    print("Testing the Dangerous URL: http://wrs49.winshipway.com/")
    print(subprocess.call(['curl','http://wrs49.winshipway.com/']))
    
    print("Testing the Highly Suspicious URL: http://wrs65.winshipway.com/")
    print(subprocess.call(['curl','http://wrs65.winshipway.com/']))
    
    print("Testing the Suspicious URL: http://wrs70.winshipway.com/")
    print(subprocess.call(['curl','http://wrs70.winshipway.com/']))
    
    print("Testing the Unrated URL: http://wrs71.winshipway.com/")
    print(subprocess.call(['curl','http://wrs71.winshipway.com/']))
    
    print("Testing the Normal URL: http://wrs81.winshipway.com/")
    print(subprocess.call(['curl','http://wrs81.winshipway.com/']))
    
    if ("off" in current_state):
        modifywrsstate(policy_id, configuration, api_version, overrides, "off")
    send_heartbeat(user_os)
    print("---Web Reputation Test Completed---")
    
def checkifwrson(policy_id, configuration, api_version, overrides):
    policies_api = deepsecurity.PoliciesApi(deepsecurity.ApiClient(configuration))
    current_wrs_settings = policies_api.describe_policy(policy_id, api_version, overrides=False)
    return(current_wrs_settings.web_reputation.state)

def modifywrsstate(policy_id, configuration, api_version, overrides, on_off):
    print("Changing the WRS state to: " + on_off)
    policies_api = deepsecurity.PoliciesApi(deepsecurity.ApiClient(configuration))
    current_wrs_settings = policies_api.describe_policy(policy_id, api_version, overrides=False)
    #Configure sending policy updates when the policy changes
    web_reputation_policy_extension = deepsecurity.WebReputationPolicyExtension()
    web_reputation_policy_extension.state = on_off
    policy = deepsecurity.Policy()
    policy.web_reputation = web_reputation_policy_extension
         
    # Modify the policy on Deep Security Manager
    modified_policy = policies_api.modify_policy(policy_id, policy, api_version)

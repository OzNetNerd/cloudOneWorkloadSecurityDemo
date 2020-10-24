import deepsecurity
from libs.utils import run_command, getacstatus, send_heartbeat
import time


def application_control_attack(host_id, policy_id, configuration, api_version, overrides, user_os, **kwargs):
    print("---Running The Application Control Test---")
    #Check if Application control is already enabled
    enabled = False
    policies_api = deepsecurity.PoliciesApi(deepsecurity.ApiClient(configuration))
    application_control_policy_extension = deepsecurity.ApplicationControlPolicyExtension()
    if(application_control_policy_extension.state is not None):
       if("on" in application_control_policy_extension.state):
           enabled = True
        
    #If application control is not enabled, enable it
    if(enabled == False):
        print("Enabling Application Control")
        enabledisableapplicationcontrol(policy_id, policies_api, application_control_policy_extension, api_version, "on")
        done = False
        while done == False:
            print("Waiting for Application Control Baseline to finish...")
            #put a sleep here to allow the policy to update and the baseline to start
            time.sleep(30)
            status = getacstatus(host_id, policy_id, configuration, api_version, overrides)
            if(status is not None):
                if("sending policy" in status.lower() or "application control inventory scan in progress" in status.lower() or "security update in progress" in status.lower()):
                    time.sleep(10)
            else:
                print("Application Control Baseline complete")
                done = True
        
    #Run the tests
    run_attack(user_os)
    
    if(enabled == False):
        enabledisableapplicationcontrol(policy_id, policies_api, application_control_policy_extension, api_version, "off")
        
    #Clean up after the tests and reset the system to it's original state
    cleanup(policy_id, policies_api, application_control_policy_extension, api_version, enabled, user_os)
    send_heartbeat(user_os)
    print("---Application Control Test Completed---")
    
def enabledisableapplicationcontrol(policy_id, policies_api, application_control_policy_extension, api_version, state):
    print("Setting the Application Control state to: " + state)
    application_control_policy_extension.state = state
    application_control_policy_extension.block_unrecognized = "true"
    policy = deepsecurity.Policy()
    policy.application_control = application_control_policy_extension
         
    # Modify the policy on Deep Security Manager
    modified_policy = policies_api.modify_policy(policy_id, policy, api_version)
    #pprint(modified_policy)      
        
def run_attack(user_os):
    if("ubuntu" in user_os):
        # Attempt to install docker
        cmd = "sudo apt install docker &" 
        output = run_command(cmd)
    if("redhat" in user_os):
        # Attempt to install docker
        cmd = "sudo yum install docker -y &" 
        output = run_command(cmd)
        cmd = "sudo docker --version" 
        output = run_command(cmd)
    if("windows" in user_os):
        cmd = "curl https://download.docker.com/win/stable/Docker%20Desktop%20Installer.exe -o dockerinstaller.exe" 
        output = run_command(cmd)
        cmd = "dockerinstaller.exe" 
        output = run_command(cmd)
    
def cleanup(policy_id, policies_api, application_control_policy_extension, api_version, enabled, user_os):
    if("ubuntu" in user_os):
        # Remove docker
        cmd = "sudo apt-get --purge remove docker -y &"
        output = run_command(cmd)
        # Not sure why I have to do this twice
        cmd = "sudo apt-get --purge remove docker -y &"
        output = run_command(cmd)
    if("redhat" in user_os):
        # Remove docker
        cmd = "sudo yum remove docker -y &"
        output = run_command(cmd)
    if("windows" in user_os):
        cmd = "del dockerinstaller.exe" 
        output = run_command(cmd)
import deepsecurity
from deepsecurity.rest import ApiException
from subprocess import Popen, PIPE
from libs.utils import get_rule_id, check_if_rule_assigned, get_last_im_scan, run_command, send_heartbeat
import time

RULE_MAP = {
    'linux': 'Unix - Open Port Monitor',
    'windows': "Microsoft Windows - 'Hosts' file modified"
}

# This is the Integrity Monitoring test
# The integrity monitoring test will check if the IM rule has been assigned
# If it's not assigned the test will assign it
#    On Linux the test will open a port using netcat and run a scan for integrity
#    On Windows the test will update the hosts file and run a scan for integrity
# This should result in detected changes to the system
# If the rule was not assigned originally, the rule will be removed from the policy
# The test will also perform a heartbeat to ensure the events get back to 
# Cloud One Workload Security or Deep Security Manager
def integrity_monitoring_attack(host_id, policy_id, configuration, api_version, overrides, user_os):
    rule_to_apply = RULE_MAP[user_os]

    print("---Running The Integrity Monitoring Test---")
    # Get the IM Rule ID
    rule_id = get_rule_id(configuration, api_version, "im", rule_to_apply)

    # Check if the rule is assigned to the policy
    found = check_if_rule_assigned(rule_to_apply, "im", rule_id, policy_id, configuration, api_version, overrides)

    # If the rule is not assigned, then assign it
    if not found:
        assign_im_rule(rule_to_apply, rule_id, policy_id, configuration, api_version, overrides, True)

    # Run the tests
    run_attack(host_id, policy_id, configuration, api_version, overrides, user_os)

    # If the rule was not originally assigned, remove it to restore the state of the policy
    if not found:
        assign_im_rule(rule_to_apply, rule_id, policy_id, configuration, api_version, overrides, False)

    # Perform a heartbeat to get the events to Cloud One or Deep Security Manager
    send_heartbeat(user_os)
    print("---Integrity Monitoring Test Completed---")


# This function will assign the rule to the policy if it is not already assigned
# If add_rule is True then it will assign the rule
# If add_rule is False then it will remove the rule from the policy
def assign_im_rule(rule_to_apply, rule_id, policy_id, configuration, api_version, overrides, add_rule):
    try:
        # Get the current list of rules from the policy
        policies_api = deepsecurity.PoliciesApi(deepsecurity.ApiClient(configuration))
        current_rules = policies_api.describe_policy(policy_id, api_version, overrides=False)

        # Add the rule_id if it doesn't already exist in current_rules
        if add_rule:
            print("Adding the " + rule_to_apply + " rule to the policy")
            if current_rules.integrity_monitoring.rule_ids is None:
                current_rules.integrity_monitoring.rule_ids = rule_id

            elif rule_id not in current_rules.integrity_monitoring.rule_ids:
                current_rules.integrity_monitoring.rule_ids.append(rule_id)
        # Remove the rule_id if it was originally unassigned
        else:
            print("Removing the " + rule_to_apply + " rule from the policy")
            current_rules.integrity_monitoring.rule_ids.remove(rule_id)

        # Add the new and existing intrusion prevention rules to a policy
        integrity_monitoring_policy_extension = deepsecurity.IntegrityMonitoringPolicyExtension()
        integrity_monitoring_policy_extension.rule_ids = current_rules.integrity_monitoring.rule_ids
        policy = deepsecurity.Policy()
        policy.integrity_monitoring = integrity_monitoring_policy_extension

        # Configure sending policy updates when the policy changes
        policy.auto_requires_update = "on"

        # Modify the policy on Deep Security Manager
        modified_policy = policies_api.modify_policy(policy_id, policy, api_version)
    except ApiException as e:
        print(
            "An exception occurred when calling PolicyIntegrityMonitoringRuleAssignmentsRecommendationsApi.add_integrity_monitoring_rule_ids_to_policy: %s\n" % e)

    # This function will run the test


# For Linux it will open a port using netcat and then run a scan for integrity
#    After the scan for integrity the netcat process will be killed
# For Windows it will make a copy of the original hosts file then update the hosts file with a new entry
#    Then a scan for integrity will be triggered
#    After the scan for integrity the hosts file will be returned to it's original state
def run_attack(host_id, policy_id, configuration, api_version, overrides, user_os):
    # Run the test for Linux
    if user_os == 'linux':
        cmd = "netcat -l 54321 &"
        print("Running command: " + cmd)
        process_info = Popen(cmd, shell=True, stdout=PIPE, stderr=PIPE, universal_newlines=True, close_fds=True)
        run_scan_for_integrity(host_id, policy_id, configuration, api_version, overrides, user_os)
        cmd = "pgrep netcat"
        output = run_command(cmd)
        if output:
            process_pid = output
            cmd = "kill -9 " + process_pid
            output = run_command(cmd)
    # Run the test for Windows   
    elif user_os == 'windows':
        cmd = "copy %WINDIR%\System32\Drivers\Etc\Hosts . /Y"
        output = run_command(cmd)
        cmd = "echo 0.0.0.0 hackersite.com >> %WINDIR%\System32\Drivers\Etc\Hosts"
        output = run_command(cmd)
        run_scan_for_integrity(host_id, policy_id, configuration, api_version, overrides, user_os)
        cmd = "copy hosts %WINDIR%\System32\Drivers\Etc\Hosts /Y"
        output = run_command(cmd)
        cmd = "del hosts"
        output = run_command(cmd)


# This function will call the dsa_control to trigger a scan for integrity
def run_scan_for_integrity(host_id, policy_id, configuration, api_version, overrides, user_os):
    print(
        "Running a scan for integrity (Note: this will time out after 3 minutes and continue on if the scan is not complete)")
    # Run the integrity scan from Linux
    if user_os == 'linux':
        cmd = "sudo /opt/ds_agent/dsa_control -m \"IntegrityScan:true\""
        output = run_command(cmd)
        check_status(host_id, policy_id, configuration, api_version, overrides)
    # Run the integrity scan from Windows
    elif user_os == 'windows':
        cmd = "\"C:\Program Files\Trend Micro\Deep Security Agent\dsa_control\" -m \"IntegrityScan:true\""
        output = run_command(cmd)
        check_status(host_id, policy_id, configuration, api_version, overrides)


# This function will check the status of the agent
# It is checking the last integrity scan time and comparing with the time the 
# test was started.  When the scan is complete the last scan time will be updated
# and the last scan time will be newer than the time the test started
# This way we can know that the scan has completed
def check_status(host_id, policy_id, configuration, api_version, overrides):
    # Set a timeout in case the IM Scan takes a long time
    timeout = 180

    # Get the current time at the start of the test
    current_time = int(time.time())

    # Get the last IM Scan time
    last_scan_time = get_last_im_scan(host_id, policy_id, configuration, api_version, overrides)

    # Check the last scan time for each of the computers
    # Loop until all the scans are completed
    done = False
    count = 0
    while done == False and count < timeout:
        if last_scan_time:
            last_scan_time = int(str(last_scan_time)[:10])
            if last_scan_time > current_time:
                print("Scan for integrity complete")
                done = True

            else:
                print("Scan for integrity not complete, waiting...")
                last_scan_time = get_last_im_scan(host_id, policy_id, configuration, api_version, overrides)
                time.sleep(1)
                count += 1
        else:
            print("Scan for integrity not complete, waiting...")
            last_scan_time = get_last_im_scan(host_id, policy_id, configuration, api_version, overrides)
            time.sleep(1)
            count += 1

    # If we reach the timeout, it doesn't necessarily mean the scan will fail, you may get events so it's worth checking.
    if count == timeout:
        print(
            "The scan for integrity has taken longer than 3 minutes.  Continuing....but please ensure the scan is complete before checking the events.")

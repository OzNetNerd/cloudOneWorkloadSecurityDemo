import sys
import os
import warnings
from getpass import getpass
import deepsecurity
from deepsecurity.rest import ApiException

from libs.anti_malware import anti_malware_attack
from libs.intrusion_prevention import ips_attack
from libs.web_reputation import web_reputation_attack
from libs.integrity_monitoring import integrity_monitoring_attack
from libs.log_inspection import log_inspection_attack
from libs.application_control import application_control_attack
from libs.docker_am import docker_am_attack


API_VERSION = 'v1'
OVERRIDES = False
WS_API_KEY = os.environ.get('WS_API_KEY')
MAX_ATTACK_NUM = 8


ATTACK_MAP = {
    1: anti_malware_attack,
    2: ips_attack,
    3: integrity_monitoring_attack,
    4: web_reputation_attack,
    5: log_inspection_attack,
    6: application_control_attack,
    7: docker_am_attack,
}


def get_host_id(hostname_id_map):
    while True:
        for host_name, computer_id in hostname_id_map.items():
            print(f"Would you like to use {host_name}? (y/n): ")
            correct_host = input().lower()

            if correct_host == 'y':
                print(f"Using host: {host_name} (computer ID {computer_id})")
                return computer_id


def get_hostname_id_map(configuration, api_version, overrides, policy_id):
    hostname_id_map = {}

    try:
        computer_instance = deepsecurity.ComputersApi(deepsecurity.ApiClient(configuration))
        computers = computer_instance.list_computers(api_version, overrides=overrides)

    except ApiException as e:
        sys.exit(e)

    for computer in computers.computers:
        if computer.policy_id == policy_id:
            host_name = computer.host_name
            computer_id = computer.id

            hostname_id_map[host_name] = computer_id

        if not hostname_id_map:
            exit("There are no hosts with the selected policy assigned. Please assign the policy to the host under "
                 "attack and re-run the script.")

    return hostname_id_map


def get_policy_id(configuration, api_version, overrides, policy_name):
    policy_instance = deepsecurity.PoliciesApi(deepsecurity.ApiClient(configuration))

    try:
        policies = policy_instance.list_policies(api_version, overrides=overrides)

    except ApiException as e:
        sys.exit(e)

    for policy in policies.policies:
        if policy.name == policy_name:
            return policy.id

    sys.exit(f'Error: Could not find policy ID for {policy_name}')


def get_ws_configuration():
    if not sys.warnoptions:
        warnings.simplefilter("ignore")

    if WS_API_KEY:
        ws_api_key = WS_API_KEY

    else:
        ws_api_key = getpass('Please enter your Workload Security API key: ')

    configuration = deepsecurity.Configuration()
    configuration.host = 'https://cloudone.trendmicro.com:443/api'
    configuration.api_key['api-secret-key'] = ws_api_key

    return configuration


def get_os():
    os_name = os.uname().sysname

    if 'linux' in os_name.lower():
        return 'linux'

    else:
        return 'windows'


def list_policies(configuration, api_version, overrides):
    policy_names = []

    try:
        policy_instance = deepsecurity.PoliciesApi(deepsecurity.ApiClient(configuration))
        policy_response = policy_instance.list_policies(api_version, overrides=overrides)

        for policy in policy_response.policies:
            policy_names.append(policy.name)

        return policy_names

    except ApiException as e:
        sys.exit(e)


def get_policy_name(configuration, api_version, overrides):
    # List the policies available and print them out so the user can choose
    available_policies = list_policies(configuration, api_version, overrides)
    count = 1

    for policy in available_policies:
        print(str(count) + " = " + policy)
        count += 1

    selected_policy_num = 0

    while not selected_policy_num or selected_policy_num > count:
        selected_policy_num = input("\nEnter the number of the policy which you would like to use: ")

        if not selected_policy_num:
            continue

        selected_policy_num = int(selected_policy_num)

        if not 1 <= selected_policy_num <= count:
            continue

        policy_num = selected_policy_num - 1
        policy_name = available_policies[policy_num]
        print(f"You selected: {policy_name}\n")

        return policy_name


def get_attack_num():
    attack_num = 0

    while True:
        print(
            "The available attacks are:\n"
            "1 = Anti-Malware\n"
            "2 = Intrusion Prevention\n"
            "3 = Integrity Monitoring\n"
            "4 = Web Reputation\n"
            "5 = Log Inspection\n"
            "6 = Application Control (Note: This attack takes about 3 minutes to run)\n"
            "7 = Docker Anti-Malware (only works on Ubuntu and Redhat)\n"
            "8 = All attacks\n"
            "99 = Exit\n"
        )

        attack_num = input("Which attack would you like to perform: ")

        # re-run loop if no user input
        if not attack_num:
            continue

        attack_num = int(attack_num)

        if attack_num == 99:
            sys.exit()

        elif 1 <= attack_num <= MAX_ATTACK_NUM:
            return attack_num


class Attacks:
    def __init__(self):
        self.configuration = get_ws_configuration()

        print(
            "Welcome to the test suite for Cloud One Workload Security.\nThis script works by running a set of attacks "
            "and assigns rules at the policy level if necessary")

        # Get the Operating System information
        self.user_os = get_os()
        print("\nThe policies in your Cloud One account are:")

        # Get the policy_id
        policy_name = get_policy_name(self.configuration, API_VERSION, OVERRIDES)
        self.policy_id = get_policy_id(self.configuration, API_VERSION, OVERRIDES, policy_name)

        # Check the hosts that the policy is applied to so we can know what host
        # the attacks are being run on
        hostname_id_map = get_hostname_id_map(self.configuration, API_VERSION, OVERRIDES, self.policy_id)
        self.host_id = get_host_id(hostname_id_map)

    def run(self):
        # Check with the user what attack they want to run
        attack_num = get_attack_num()

        if attack_num == MAX_ATTACK_NUM:
            for attack_entry in range(1, MAX_ATTACK_NUM):
                attack_object = ATTACK_MAP[attack_entry]
                attack_object(host_id=self.host_id, policy_id=self.policy_id, configuration=self.configuration,
                              api_version=API_VERSION, overrides=OVERRIDES, user_os=self.user_os)

        else:
            attack_object = ATTACK_MAP[attack_num]
            attack_object(host_id=self.host_id, policy_id=self.policy_id, configuration=self.configuration,
                          api_version=API_VERSION, overrides=OVERRIDES, user_os=self.user_os)


def main():
    attacks = Attacks()

    while True:
        attacks.run()


if __name__ == "__main__":
    main()

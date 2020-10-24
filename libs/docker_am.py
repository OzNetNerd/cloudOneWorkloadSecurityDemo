from libs.utils import run_command, getacstatus, send_heartbeat
import time

def docker_am_attack(host_id, policy_id, configuration, api_version, overrides, user_os, **kwargs):
    print("---Running The Docker Test---")
    docker_installed = False
    if("ubuntu" in user_os or "redhat" in user_os):
        print("Checking if Docker is installed")
        cmd = "sudo docker version" 
        output = run_command(cmd)
        if(output == ""):
            print("Docker not found; installing Docker")
            if("ubuntu" in user_os):
                cmd = "sudo apt-get install docker.io -y" 
                output = run_command(cmd)
            if("redhat" in user_os):
                cmd = "sudo yum install docker" 
                output = run_command(cmd)
        else:
            docker_installed = True
    
    if("windows" in user_os):
        print("This test only works on ubuntu and redhat currently.  Exiting!!")
        return()
        cmd = "docker version" 
        output = run_command(cmd)
        if("docker" in output.lower() and "version" in output.lower() and "build" in output.lower()):
            print("Found docker installed already")
            docker_installed = True
        else:
            cmd = "curl https://download.docker.com/win/stable/Docker%20Desktop%20Installer.exe -o Docker_Desktop_Installer.exe" 
            output = run_command(cmd)
            cmd = "Docker_Desktop_Installer.exe install --quiet" 
            output = run_command(cmd)
            
    run_attack(host_id, policy_id, configuration, api_version, overrides, user_os)
    
    if(docker_installed == False):
        cleanup(user_os)
    send_heartbeat(user_os)

def run_attack(host_id, policy_id, configuration, api_version, overrides, user_os):
    if("ubuntu" in user_os or "redhat" in user_os):
        cmd = "sudo docker pull philippbehmer/docker-eicar:latest" 
        output = run_command(cmd)
        cmd = "sudo docker run philippbehmer/docker-eicar:latest" 
        output = run_command(cmd)
        cmd = "sudo /opt/ds_agent/dsa_control -m \"AntiMalwareManualScan:true\""
        output = run_command(cmd)
        time.sleep(10)
        checkstatus(host_id, policy_id, configuration, api_version, overrides)
        
def cleanup(user_os):
    print("Uninstalling Docker")
    if("ubuntu" in user_os):
        cmd = "sudo apt-get --purge remove docker.io -y" 
        output = run_command(cmd)
    if("redhat" in user_os):
        cmd = "sudo yum remove docker" 
        output = run_command(cmd)
    if("windows" in user_os):
        cmd = "Docker_Desktop_Installer.exe uninstall --quiet" 
        output = run_command(cmd)
        
def checkstatus(host_id, policy_id,configuration, api_version, overrides):
    done = False
    while done == False:
        print("Checking the computer status...")
        status = getacstatus(host_id, policy_id, configuration, api_version, overrides)
        if(status is not None):
            time.sleep(10)
        else:
            print("Done")
            done = True
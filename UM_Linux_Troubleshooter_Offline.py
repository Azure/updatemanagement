#!/usr/bin/env python

import sys
import os
import os.path
import socket
import datetime
import imp
import codecs
import json
import string
import platform
import re
import time
from urlparse import urlparse
import subprocess
from os import walk

rule_info_list = []
output = []

oms_admin_conf_path = "/etc/opt/microsoft/omsagent/conf/omsadmin.conf"
oms_agent_dir = "/var/opt/microsoft/omsagent"
oms_agent_log = "/var/opt/microsoft/omsagent/log/omsagent.log"
current_mof = "/etc/opt/omi/conf/omsconfig/configuration/Current.mof"
status_passed = "Passed"
status_failed = "Failed"
status_debug = "Debug"
empty_failure_reason = ""
workspace = ""

class RuleInfo:
    def __init__(self, rule_id, rule_group_id, status, result_msg_id):
        self.RuleId = rule_id
        self.RuleGroupId = rule_group_id
        self.CheckResult = status
        self.CheckResultMessageId = result_msg_id
        self.CheckResultMessageArguments = list()

def enum(**enums):
    return type('Enum', (), enums)

def printDebug(*args):
    args = [str(x) for x in args]
    msg = ''.join(args)
    print("RepoAccessCheck:: " + msg)

OSType = enum(NotAvailable = 0, Ubuntu = 1, Suse = 2, Redhat = 3, CentOs = 4)

#####################################
def RunGetOutput(cmd, no_output, chk_err=False):
    """
    Wrapper for subprocess.check_output.
    Execute 'cmd'.  Returns return code and STDOUT,
    trapping expected exceptions.
    Reports exceptions to Error if chk_err parameter is True
    """

    def check_output(no_output, *popenargs, **kwargs):
        """
        Backport from subprocess module from python 2.7
        """
        if 'stdout' in kwargs:
            raise ValueError('stdout argument not allowed, it will be overridden.')
        if no_output:
            out_file = None
        else:
            out_file = subprocess.PIPE
        process = subprocess.Popen(stdout=out_file, *popenargs, **kwargs)
        output, unused_err = process.communicate()
        retcode = process.poll()
        if retcode:
            cmd = kwargs.get("args")
            if cmd is None:
                cmd = popenargs[0]
            raise subprocess.CalledProcessError(retcode, cmd, output=output)
        return output

    # Exception classes used by this module.
    class CalledProcessError(Exception):

        def __init__(self, returncode, cmd, output=None):
            self.returncode = returncode
            self.cmd = cmd
            self.output = output

        def __str__(self):
            return "Command '%s' returned non-zero exit status %d" \
                   % (self.cmd, self.returncode)

    subprocess.check_output = check_output
    subprocess.CalledProcessError = CalledProcessError
    try:
        output = subprocess.check_output(
            no_output, cmd, stderr=subprocess.STDOUT, shell=True)
    except subprocess.CalledProcessError, e:
        if no_output:
            return e.returncode, None
        else:
            return e.returncode, e.output.decode('utf8', 'ignore').encode('ascii', 'ignore')
    if no_output:
        return 0, None
    else:
        return 0, output.decode('utf8', 'ignore').encode('ascii', 'ignore')

#####################################


class RepositoryManager:
    def __init__(self):
        self.logs = [] #List of tuple of msg and status

    def appendToLogs(self, msg, status):
        self.logs.append((msg, status))

    def checkRule(self):
        osInQuestion = get_os_type()

        repoUriList = self.getConfiguredRepos(osInQuestion)
        if repoUriList is None:
            return 0  #failed
        status = self.pingRepos(repoUriList)  #uncomment this

        if status == 0:
            self.appendToLogs("Access Check for Repo failed !", status_debug)
        return status

    def getConfiguredRepos(self, osType):
        #support for rhel, ubuntu, suse, centos
        if osType == OSType.Ubuntu:
            repoList = self.getConfiguredReposForUbuntu() 
        elif osType == OSType.Suse:
            repoList = self.getConfiguredReposForSuse()
        elif osType == OSType.Redhat:
            repoList = self.getConfiguredReposForRhel()
        elif osType == OSType.CentOs:
            repoList = self.getConfiguredReposForCentos()
        else:
            self.appendToLogs("OS Not Supported")
            repoList = None #os type not supported.
        return repoList

    def getConfiguredReposForSuse(self):
        repoDirectory = "/etc/zypp/repos.d/"
        if os.path.exists(repoDirectory) is False:
            self.appendToLogs("Error - Repo Directory /etc/zypp/repos.d/ not present", status_debug)
            return None

        unixCmd = "zypper refresh"

        self.appendToLogs("Refereshing Zypper Repos", status_debug)
        code, out = RunGetOutput(unixCmd, False, False)
        if code == 0:
            self.appendToLogs("Success: Repositories refereshed successfully.", status_debug)
            return [] #success, repositories successfully refreshed means also accessible


    def getConfiguredReposForRhel(self):
        repoDirectory = "/etc/yum.repos.d/"
        if os.path.exists(repoDirectory) is False:
            self.appendToLogs("Error - Repo Directory /etc/yum.repos.d/ not present", status_debug)
            return None
        
        unixCmd =  "grep -roEh 'https?://[-A-Za-z0-9+&@#/%?=~_|!:,.;]*[-A-Za-z0-9+&@#/%=~_|]' /etc/yum.repos.d"
        (out, err) = self.executeCommand(unixCmd)

        if err != '':
            self.appendToLogs("Error while extracted repos -- " + err, status_debug)
            return None

        repoList = []
        out = out.split("\n")
        for o in out:
            if len(o) > 2:
                repoList.append(o)
        return repoList

    def getConfiguredReposForCentos(self):
        repoDirectory = "/etc/yum.repos.d/"
        if os.path.exists(repoDirectory) is False:
            self.appendToLogs("Error - Repo Directory /etc/yum.repos.d/ not present", status_debug)
            return None
        
        unixCmd =  "grep -roEh 'https?://[-A-Za-z0-9+&@#/%?=~_|!:,.;]*[-A-Za-z0-9+&@#/%=~_|]' /etc/yum.repos.d"
        (out, err) = self.executeCommand(unixCmd)

        if err != '':
            self.appendToLogs("Error while extracted repos -- " + err, status_debug)
            return None

        repoList = []
        out = out.split("\n")
        for o in out:
            if len(o) > 2:
                repoList.append(o)
        return repoList

    def getConfiguredReposForUbuntu(self):
        repoFile = "/etc/apt/sources.list"
        if os.path.isfile(repoFile) is False:
            self.appendToLogs("Error - Repo File /etc/apt/sources.list not present", status_debug)
            return None
        
        unixCmd = "grep -Erh ^deb /etc/apt/sources.list*"
        (out, err) = self.executeCommand(unixCmd)

        if err != '':
            self.appendToLogs("Error while extracted repos -- " + err, status_debug)
            return None
        
        out = out.split("\n")
        repoList = []
        for str in out:
            strList = str.split(" ")
            if len(strList) >= 2: #format: "deb uri", excluding space or other invalid strings
                repoList.append(strList[1])
        return repoList


    def executeCommand(self, unixCmd):
        proc = subprocess.Popen(unixCmd,
                                stdin = subprocess.PIPE,
                                stdout = subprocess.PIPE,
                                stderr = subprocess.PIPE,
                                shell=True
                            )
        (out, err) = proc.communicate()
        return (out, err)

    def pingRepos(self, repoUris):
        if len(repoUris) == 0:
            return 1 #success, nothing to check

        repoUris = self.extractNetLocFromUris(repoUris)
        self.appendToLogs("Extracted RepoURI netloc List: " + str(set(repoUris)), status_debug)

        status = 1
        for uri in repoUris:
            status &= self.pingEndpoint(uri)  #not stopping here, because want to ping all uris present
            
        if status == 0:
            self.appendToLogs("Error - Not able to ping all repositories!", status_debug)
            return 0  #failure
        return 1  #success

    def pingEndpoint(self, uri):
        hostname = uri
        response = os.system("ping -c 1 " + hostname + " >/dev/null 2>&1")

        if response == 0:
            self.appendToLogs(hostname + ' Ping successful!', status_debug)
            return 1

        sleep_wait=1
        max_ping_wait=2
        count=0
        #will try pinging till 2 seconds.
        while (count < max_ping_wait and os.system("ping -c 1 " + hostname + " >/dev/null 2>&1")):
            time.sleep(sleep_wait)
            count+=1

        if (count < max_ping_wait):
            self.appendToLogs(hostname + ' Ping successful!', status_debug)
            return 1
        else:
            self.appendToLogs(hostname + ' Ping unsuccessful.', status_debug)
            return 0

    def extractNetLocFromUris(self, repoUris):
        netLocList = []
        for uri in repoUris:
            currentNetLoc = None
            parsed = urlparse(uri)
            if parsed.netloc == '':  #since netloc is empty, possible it's present in path
                path = parsed.path
                if path is not None:
                    if "/" not in path:  #case of uri 'google.com'
                        currentNetLoc = path
                    else:
                        path = path.split("/")
                        if path[0] == '':  #case of uri "/google.com/path/to"
                            if path[1] != '':
                                currentNetLoc = path[1]
                        else:              #case of uri "google.com/path/to" 
                            currentNetLoc = path[0]
            else:
                currentNetLoc = parsed.netloc   # got netloc

            if currentNetLoc is None:
                self.appendToLogs("Unable to get netLoc for URI: " + uri + " Skipping it...", status_debug)
            else:
                netLocList.append(currentNetLoc)   

        netLocList = list(set(netLocList))
        return netLocList  

def check_access_to_linux_repos():
    rule_id = "Linux.ReposAccessCheck"
    rule_group_id = "connectivity"

    repoMgr = RepositoryManager()
    status = repoMgr.checkRule()
    logs = repoMgr.logs

    for log in logs:
        write_log_output(rule_id, rule_group_id, log[1], empty_failure_reason, log[0])

    if status == 0:
        write_log_output(rule_id, rule_group_id, status_failed, empty_failure_reason, "Some of the repositories configured could not be accessed")
    else:
        write_log_output(rule_id, rule_group_id, status_passed, empty_failure_reason, "Repositories Configured Properly & Accessible")

def main(output_path=None, return_json_output="False"):
    if os.geteuid() != 0:
        print "Please run this script as root"
        exit()

    # supported python version 2.4.x to 2.7.x
    if not ((sys.version_info[0] == 2) and ((sys.version_info[1]>=4) and (sys.version_info[1] < 8))):
        print("Unsupport python version:" + str(sys.version_info))
        exit()


    print "Processing Information...[can take upto 5 minutes]"
    global workspace
    workspace = get_workspace()

    get_machine_info()
    check_os_version()
    check_oms_agent_installed()
    check_oms_agent_running()
    check_multihoming()
    check_hybrid_worker_package_present()
    check_hybrid_worker_running()
    check_proxy_connectivity()
    check_imds_connectivity()
    check_general_internet_connectivity()
    check_agent_service_endpoint()
    check_jrds_endpoint(workspace)
    check_log_analytics_endpoints()

    try:
        check_access_to_linux_repos()
    except:
        pass

    if return_json_output == "True":
        print json.dumps([obj.__dict__ for obj in rule_info_list])
    else:
        for line in output:
            print line

        if output_path is not None:
            try:
                os.makedirs(output_path)
            except OSError:
                if not os.path.isdir(output_path):
                    raise
            log_path = "%s/healthcheck-%s.log" % (output_path, datetime.datetime.utcnow().isoformat())
            f = open(log_path, "w")
            f.write("".join(output))
            f.close()
            print "Output is written to " + log_path

def get_machine_info():
    FNULL = open(os.devnull, "w")
    if subprocess.call(["which", "hostnamectl"], stdout=FNULL, stderr=FNULL) == 0:
        hostname_output = os.popen("hostnamectl").read()
        write_log_output(None, None, status_debug, empty_failure_reason, "Machine Information:" + hostname_output)
    FNULL.close()
    return hostname_output

def get_os_type():
    vmMachineInfo = get_machine_info()
    if vmMachineInfo is None:
        vmMachineInfo = ""

    os_version = platform.platform()
    if re.search("Ubuntu", os_version, re.IGNORECASE) != None or re.search("Ubuntu", vmMachineInfo, re.IGNORECASE) != None:
        return OSType.Ubuntu
    elif re.search("SuSE", os_version, re.IGNORECASE) != None or re.search("suse", vmMachineInfo, re.IGNORECASE) != None:
        return OSType.Suse
    elif re.search("redhat", os_version, re.IGNORECASE) != None or re.search("red hat", vmMachineInfo, re.IGNORECASE) != None:
        return OSType.Redhat
    elif re.search("centos", os_version, re.IGNORECASE) != None or re.search("centos", vmMachineInfo, re.IGNORECASE) != None:
        return OSType.CentOs
    else:
        return OSType.NotAvailable

def check_os_version():
    rule_id = "Linux.OperatingSystemCheck"
    rule_group_id = "prerequisites"

    os_version = platform.platform()
    supported_os_url = "https://docs.microsoft.com/en-us/azure/automation/update-management/operating-system-requirements#supported-operating-systems"
    # We support (Ubuntu 14.04, Ubuntu 16.04, SuSE 11, SuSE 12, Redhat 6, Redhat 7, CentOs 6, CentOs 7)
    if re.search("Ubuntu-14.04", os_version, re.IGNORECASE) or \
       re.search("Ubuntu-16.04", os_version, re.IGNORECASE) or \
       re.search("Ubuntu-18.04", os_version, re.IGNORECASE) or \
       re.search("Ubuntu-20.04", os_version, re.IGNORECASE) or \
       re.search("SuSE-11", os_version, re.IGNORECASE) or \
       re.search("SuSE-12", os_version, re.IGNORECASE) or \
       re.search("redhat-6", os_version, re.IGNORECASE) or \
       re.search("redhat-7", os_version, re.IGNORECASE) or \
       re.search("centos-6", os_version, re.IGNORECASE) or \
       re.search("centos-7", os_version, re.IGNORECASE) :
        write_log_output(rule_id, rule_group_id, status_passed, empty_failure_reason, "Operating system version is supported")
    else:
        log_msg = "Operating System version (%s) is not supported. Supported versions listed here: %s" % (os_version, supported_os_url)
        write_log_output(rule_id, rule_group_id, status_failed, empty_failure_reason, log_msg, supported_os_url)



def check_oms_agent_installed():
    rule_id = "Linux.OMSAgentInstallCheck"
    rule_group_id = "servicehealth"
    oms_agent_troubleshooting_url = "https://github.com/Microsoft/OMS-Agent-for-Linux/blob/master/docs/Troubleshooting.md"

    if os.path.isfile(oms_admin_conf_path) and os.path.isfile(oms_agent_log):
        write_log_output(rule_id, rule_group_id, status_passed, empty_failure_reason, "Microsoft Monitoring agent is installed")

        oms_admin_file_content = "\t"
        oms_admin_file = open(oms_admin_conf_path, "r")
        for line in oms_admin_file:
            oms_admin_file_content += line + "\t"

        oms_admin_file.close()
        write_log_output(rule_id, rule_group_id, status_debug, empty_failure_reason, "omsadmin.conf file contents:\n" + oms_admin_file_content)
    else:
        write_log_output(rule_id, rule_group_id, status_failed, empty_failure_reason, "Microsoft Monitoring agent is not installed", oms_agent_troubleshooting_url)
        write_log_output(rule_id, rule_group_id, status_debug, empty_failure_reason, "Microsoft Monitoring agent troubleshooting guide:" + oms_agent_troubleshooting_url)
        return

def check_oms_agent_running():
    rule_id = "Linux.OMSAgentStatusCheck"
    rule_group_id = "servicehealth"
    oms_agent_troubleshooting_url = "https://github.com/Microsoft/OMS-Agent-for-Linux/blob/master/docs/Troubleshooting.md"

    is_oms_agent_running, ps_output = is_process_running("omsagent", ["omsagent.log", "omsagent.conf"], "OMS Agent")
    if is_oms_agent_running:
        write_log_output(rule_id, rule_group_id, status_passed, empty_failure_reason, "Microsoft Monitoring agent is running")
    else:
        write_log_output(rule_id, rule_group_id, status_failed, empty_failure_reason, "Microsoft Monitoring agent is not running", oms_agent_troubleshooting_url)
        write_log_output(rule_id, rule_group_id, status_debug, empty_failure_reason, ps_output)
        write_log_output(rule_id, rule_group_id, status_debug, empty_failure_reason, "Microsoft Monitoring agent troubleshooting guide:" + oms_agent_troubleshooting_url)

def check_multihoming():
    rule_id = "Linux.MultiHomingCheck"
    rule_group_id = "servicehealth"

    if not os.path.isdir(oms_agent_dir):
        write_log_output(rule_id, rule_group_id, status_failed, "NoWorkspace", "Machine is not registered with log analytics workspace.")
        return

    directories = []
    potential_workspaces = []

    for (dirpath, dirnames, filenames) in walk(oms_agent_dir):
        directories.extend(dirnames)
        break # Get the top level of directories

    for directory in directories:
        if len(directory) >= 32:
            potential_workspaces.append(directory)

    workspace_id_list = str(potential_workspaces)
    if len(potential_workspaces) > 1:
        write_log_output(rule_id, rule_group_id, status_failed, empty_failure_reason, "Machine registered with more than one log analytics workspace. List of workspaces:" + workspace_id_list, workspace_id_list)
    else:
        write_log_output(rule_id, rule_group_id, status_passed, empty_failure_reason, "Machine registered with log analytics workspace:" + workspace_id_list, workspace_id_list)

def check_hybrid_worker_package_present():
    rule_id = "Linux.HybridWorkerPackgeCheck"
    rule_group_id = "servicehealth"

    if os.path.isfile("/opt/microsoft/omsconfig/modules/nxOMSAutomationWorker/VERSION") and \
       os.path.isfile("/opt/microsoft/omsconfig/modules/nxOMSAutomationWorker/DSCResources/MSFT_nxOMSAutomationWorkerResource/automationworker/worker/configuration.py"):
        write_log_output(rule_id, rule_group_id, status_passed, empty_failure_reason, "Hybrid worker package is present")
    else:
        write_log_output(rule_id, rule_group_id, status_failed, empty_failure_reason, "Hybrid worker package is not present")

def check_hybrid_worker_running():
    rule_id = "Linux.HybridWorkerStatusCheck"
    rule_group_id = "servicehealth"

    if not os.path.isfile(current_mof):
        write_log_output(rule_id, rule_group_id, status_failed, "MissingCurrentMofFile", "Hybrid worker is not running. current_mof file:(" + current_mof + ") is missing", current_mof)
        return

    search_text = "ResourceSettings"
    command = "file -b --mime-encoding " + current_mof
    current_mof_encoding = os.popen(command).read()
    resourceSetting = find_line_in_file("ResourceSettings", current_mof, current_mof_encoding);
    if resourceSetting is None:
        write_log_output(rule_id, rule_group_id, status_failed, empty_failure_reason, "Hybrid worker is not running")
        write_log_output(rule_id, rule_group_id, status_debug, empty_failure_reason, "Unable to get ResourceSettings from current_mof file:(" + current_mof + ") with file encoding:" + current_mof_encoding)
        return

    backslash = string.replace("\str", "str", "")
    resourceSetting = string.replace(resourceSetting, backslash, "")
    resourceSetting = string.replace(resourceSetting, ";", "")
    resourceSetting = string.replace(resourceSetting, "\"[", "[")
    resourceSetting = string.replace(resourceSetting, "]\"", "]")
    resourceSetting = resourceSetting.split("=")[1].strip()

    automation_worker_path = "/opt/microsoft/omsconfig/Scripts/"
    if (sys.version_info.major == 2) :
        if (sys.version_info.minor >= 6) :
            automation_worker_path += "2.6x-2.7x"
        else:
            automation_worker_path += "2.4x-2.5x"

    os.chdir(automation_worker_path)
    nxOMSAutomationWorker=imp.load_source("nxOMSAutomationWorker", "./Scripts/nxOMSAutomationWorker.py")
    settings = nxOMSAutomationWorker.read_settings_from_mof_json(resourceSetting)
    if not settings.auto_register_enabled:
        write_log_output(rule_id, rule_group_id, status_failed, "UpdateDeploymentDisabled", "Hybrid worker is not running", current_mof)
        write_log_output(rule_id, rule_group_id, status_debug, empty_failure_reason, "Update deployment solution is not enabled. ResourceSettings:" + resourceSetting)
        return

    if nxOMSAutomationWorker.Test_Marshall(resourceSetting) == [0]:
        write_log_output(rule_id, rule_group_id, status_passed, empty_failure_reason, "Hybrid worker is running")
    else:
        write_log_output(rule_id, rule_group_id, status_failed, empty_failure_reason, "Hybrid worker is not running")
        write_log_output(rule_id, rule_group_id, status_debug, empty_failure_reason, "ResourceSettings:" + resourceSetting + " read from current_mof file:(" + current_mof + ")")
        write_log_output(rule_id, rule_group_id, status_debug, empty_failure_reason, "nxOMSAutomationWorker.py path:" + automation_worker_path)

def check_proxy_connectivity():
    rule_id = "Linux.ProxyCheck"
    rule_group_id = "connectivity"

    if os.environ.get('HTTP_PROXY') is None:
        write_log_output(rule_id, rule_group_id, status_passed, empty_failure_reason, "Machine has no proxy enabled.")
    else:
        write_log_output(rule_id, rule_group_id, status_failed, empty_failure_reason, "Machine has proxy enabled.")

def check_imds_connectivity():
    rule_id = "Linux.ImdsCheck"
    rule_group_id = "connectivity"

    curl_cmd = "curl -H \"Metadata: true\" http://169.254.169.254/metadata/instance?api-version=2018-02-01"
    code, out = RunGetOutput(curl_cmd, False, False)

    if code == 0:
        write_log_output(rule_id, rule_group_id, status_debug, empty_failure_reason, "IMDS Server Information: " + str(out))
        write_log_output(rule_id, rule_group_id, status_passed, empty_failure_reason, "Machine is able to reach IMDS server.")
    else:
        write_log_output(rule_id, rule_group_id, status_failed, empty_failure_reason, "Machine is not able to reach IMDS server. Applicable to azure machines only.")

def check_general_internet_connectivity():
    rule_id = "Linux.InternetConnectionCheck"
    rule_group_id = "connectivity"

    if check_endpoint(None, "bing.com") and check_endpoint(None, "google.com"):
        write_log_output(rule_id, rule_group_id, status_passed, empty_failure_reason, "Machine is connected to internet")
    else:
        write_log_output(rule_id, rule_group_id, status_failed, empty_failure_reason, "Machine is not connected to internet")

def check_agent_service_endpoint():
    rule_id = "Linux.AgentServiceConnectivityCheck"
    rule_group_id = "connectivity"

    agent_endpoint = get_agent_endpoint()
    if  agent_endpoint is None:
        write_log_output(rule_id, rule_group_id, status_failed, "UnableToGetEndpoint", "Unable to get the registration (agent service) endpoint")
    elif  check_endpoint(None, agent_endpoint):
        write_log_output(rule_id, rule_group_id, status_passed, empty_failure_reason, "TCP test for {" + agent_endpoint + "} (port 443) succeeded", agent_endpoint)
    else:
        write_log_output(rule_id, rule_group_id, status_failed, empty_failure_reason, "TCP test for {" + agent_endpoint + "} (port 443) failed", agent_endpoint)

def check_jrds_endpoint(workspace):
    rule_id = "Linux.JRDSConnectivityCheck"
    rule_group_id = "connectivity"

    jrds_endpoint = get_jrds_endpoint(workspace)
    if jrds_endpoint is None:
        write_log_output(rule_id, rule_group_id, status_failed, "UnableToGetEndpoint", "Unable to get the operations (JRDS) endpoint")
    elif jrds_endpoint is not None and check_endpoint(workspace, jrds_endpoint):
        write_log_output(rule_id, rule_group_id, status_passed, empty_failure_reason, "TCP test for {" + jrds_endpoint + "} (port 443) succeeded", jrds_endpoint)
    else:
        write_log_output(rule_id, rule_group_id, status_failed, empty_failure_reason, "TCP test for {" + jrds_endpoint + "} (port 443) failed", jrds_endpoint)

def check_log_analytics_endpoints():
    rule_id = "Linux.LogAnalyticsConnectivityCheck"
    rule_group_id = "connectivity"

    i = 0
    if is_fairfax_region() is True:
        fairfax_log_analytics_endpoints = ["usge-jobruntimedata-prod-1.usgovtrafficmanager.net", "usge-agentservice-prod-1.usgovtrafficmanager.net",
                    "*.ods.opinsights.azure.us", "*.oms.opinsights.azure.us" ]

        for endpoint in fairfax_log_analytics_endpoints:
            i += 1
            if "*" in endpoint and workspace is not None:
                endpoint = endpoint.replace("*", workspace)

            if check_endpoint(workspace, endpoint):
                write_log_output(rule_id + str(i), rule_group_id, status_passed, empty_failure_reason, "TCP test for {" + endpoint + "} (port 443) succeeded", endpoint)
            else:
                write_log_output(rule_id + str(i), rule_group_id, status_failed, empty_failure_reason, "TCP test for {" + endpoint + "} (port 443) failed", endpoint)
    else:
        log_analytics_endpoints = ["*.ods.opinsights.azure.com", "*.oms.opinsights.azure.com", "ods.systemcenteradvisor.com"]
        for endpoint in log_analytics_endpoints:
            i += 1
            if "*" in endpoint and workspace is not None:
                endpoint = endpoint.replace("*", workspace)

            if check_endpoint(workspace, endpoint):
                write_log_output(rule_id + str(i), rule_group_id, status_passed, empty_failure_reason, "TCP test for {" + endpoint + "} (port 443) succeeded", endpoint)
            else:
                write_log_output(rule_id + str(i), rule_group_id, status_failed, empty_failure_reason, "TCP test for {" + endpoint + "} (port 443) failed", endpoint)

def check_endpoint(workspace, endpoint):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    new_endpoint = None

    if "*" in endpoint and workspace is not None:
        new_endpoint = endpoint.replace("*", workspace)
    elif "*" not in endpoint:
        new_endpoint = endpoint

    if new_endpoint is not None:
        try:
            response = sock.connect_ex((new_endpoint, 443))

            if response == 0:
                return True
            else:
                return False

        except Exception as ex:
            return False
    else:
        return False


def get_jrds_endpoint(workspace):
    if workspace is not None:
        worker_conf_path = "/var/opt/microsoft/omsagent/%s/state/automationworker/worker.conf" % (workspace)
        line = find_line_in_file("jrds_base_uri", worker_conf_path)
        if line is not None:
            return line.split("=")[1].split("/")[2].strip()

    return None

def get_agent_endpoint():
    line = find_line_in_file("agentsvc", oms_admin_conf_path)
    # Fetch the text after https://
    if line is not None:
        return line.split("=")[1].split("/")[2].strip()

    return None

def is_process_running(process_name, search_criteria, output_name):
    command = "ps aux | grep %s | grep -v grep" % (process_name)
    grep_output = os.popen(command).read()
    if any(search_text in grep_output for search_text in search_criteria):
        return True, grep_output
    else:
        return False, grep_output

def get_workspace():
    line = find_line_in_file("WORKSPACE", oms_admin_conf_path)
    if line is not None:
        return line.split("=")[1].strip()

    return None

def is_fairfax_region():
    oms_endpoint = find_line_in_file("OMS_ENDPOINT", oms_admin_conf_path)
    if oms_endpoint is not None:
        return ".us" in oms_endpoint.split("=")[1]

def find_line_in_file(search_text, path, file_encoding=""):
    if os.path.isfile(path):
        if file_encoding == "":
            current_file = open(path, "r")
        else:
            current_file = codecs.open(path, "r", file_encoding)

        for line in current_file:
            if search_text in line:
                current_file.close()
                return line

        current_file.close()
    return None


def write_log_output(rule_id, rule_group_id, status, failure_reason, log_msg, *result_msg_args):
    global output, rule_info_list

    if(type(log_msg) != str):
        log_msg = str(log_msg)

    if status != status_debug:
        if failure_reason == empty_failure_reason:
            result_msg_id = rule_id + "." + status
        else:
            result_msg_id = rule_id + "." + status + "." + failure_reason

        current_rule_info = RuleInfo(rule_id, rule_group_id, status, result_msg_id)

        result_msg_args_list = []
        for arg in result_msg_args:
            current_rule_info.CheckResultMessageArguments.append(arg)

        rule_info_list.append(current_rule_info)

    output.append(status + ": " + log_msg + "\n")

if __name__ == "__main__":
    if len(sys.argv) > 2:
        main(sys.argv[1], sys.argv[2])
    elif len(sys.argv) > 1:
        main(sys.argv[1])
    else:
        main()

import sys
import os
import shutil
import atexit
from subprocess import call
import re
import random
import k8sdeployment


def ip2mac(ip_address):
    mac_address = "0a:58"
    for dec in ip_address.split("."):
        if int(dec) < 16:
            mac_address += ":0" + '{0:x}'.format(int(dec))
        else:
            mac_address += ":" '{0:x}'.format(int(dec))
    return mac_address


# only synchronize filenames in the folders not file contents
# folder1 and 2 will contains the same list of files:
def synch_folder_file_names(folder1, folder2):
    files1 = os.listdir(folder1)
    files2 = os.listdir(folder2)

    file_set = set(files1 + files2)

    for f in (file_set - set(files1)): # files missing from folder 1
        open(folder1 + "/" + f, 'a').close() # create empy file

    for f in (file_set - set(files2)): # files missing from folder 2
        open(folder2 + "/" + f, 'a').close() # create empty file


# remove empty files from a folder: this is a "cleaning" process
def remove_empty_files(folder):
    files = os.listdir(folder)

    for f in files:
        if (os.stat(folder + "/" + f).st_size == 0): # delete empty files
            os.remove(folder + "/" + f)


def clear_ovs_tables_on_nodes(node_list):
    for node in node_list.values():
        call(["ovs-ofctl", "del-flows", "tcp:{node_ip}:16633".format(node_ip=node.ip_address)])
        call(["ovs-ofctl", "-O", "OpenFlow13", "del-groups", "tcp:{node_ip}:16633".format(node_ip=node.ip_address)])


def create_ovs_ruleset_for_each_node(node_list, service_list, pod_list):
    if not os.path.exists("config"):
        os.makedirs("config", exist_ok=True)
        rel_path = "config"
    else:
        delete_tmp_if_exist()
        os.makedirs("tmp")
        rel_path = "tmp"

    for node in node_list.values():

        flow_file = rel_path + "/" + node.name + ".flows"
        group_file = rel_path + "/" + node.name + ".groups"

        with open(flow_file, "w") as flows, \
             open(group_file, "w") as groups:
            # TODO: pod backend nelkul maradt service kezelese
            # TODO: global CIDR es service IP dinamikus kezelese
            # TABLE 0 - DEFAULT rules
            flows.write("table=0,priority=41000,arp,action=normal\n")
            flows.write("table=0,priority=50,in_port:1,action=goto_table:5\n")
            flows.write("table=0,priority=90,ip,nw_dst={node_gw}/32,actions=set_field:{mac_address}->eth_dst,output:LOCAL\n".format(node_gw=pod_cidr_to_node_gw(node.pod_cidr), mac_address=ip2mac(pod_cidr_to_node_gw(node.pod_cidr))))
            flows.write("table=0,priority=33,ip,nw_src=10.244.0.0/16,nw_dst=192.168.0.0/16,action=goto_table:2\n")
            flows.write("table=0,priority=33,ip,nw_src=172.16.0.0/16,nw_dst=192.168.0.0/16,action=goto_table:2\n")
            flows.write("table=0,priority=33,ip,nw_src=10.244.0.0/16,nw_dst=10.96.0.0/12,action=goto_table:3\n")
            flows.write("table=0,priority=30,ip,nw_dst=10.244.0.0/16,action=goto_table:4\n")
            flows.write("table=0,priority=10,ip,action=LOCAL\n")

            # TABLE 2 - un-DNAT: pod <-- service
            for service in service_list.values():
                for port in service.ports:
                    for pod in pod_list.values(): # create one rule for each "port - pod" pair
                        if k8sdeployment.pod_belongs_to_service(pod, service):
                            flows.write(
                                "table=2,priority=100,ip,nw_src={pod_ip},{protocol},tp_src={target_port},actions=load:2804->NXM_OF_IP_DST[16..31],set_field:{cluster_ip}->nw_src,set_field:{source_port}->{protocol}_src,resubmit(,4)\n".format(
                                    pod_ip=pod.ip_address, protocol=port.protocol.lower( ), target_port=port.target,
                                    cluster_ip=service.cluster_ip, source_port=port.source))

            # catch rule for TABLE 2
            flows.write("table=2,priority=1,ip,action=goto_table:4\n")

            # TABLE 3 - DNAT: pod --> service
            group_id = 1000
            for service in service_list.values():
                for port in service.ports:
                    if k8sdeployment.service_without_pod_backend(service, pod_list.values()):  # if there is no pod, then redirect to the master node
                        print("Service %s without POD" % service.cluster_ip)
                        flows.write("table=0,priority=70,ip,nw_dst={service_ip}/32,action=LOCAL\n".format(
                            service_ip=service.cluster_ip))
                    else:
                        # flow entry
                        flows.write(
                            "table=3,priority=33,ip,nw_dst={cluster_ip}/32,{protocol},tp_dst={source_port},actions=load:49320->NXM_OF_IP_SRC[16..31],group:{g_id}\n".format(
                                cluster_ip=service.cluster_ip, protocol=port.protocol.lower( ), source_port=port.source,
                                g_id=group_id))

                        # each group entry is a select group for NAT to all the pod backends
                        groups.write("group_id={gid},type=select".format(gid=group_id))

                        for pod in pod_list.values(): # create one rule for each "port - pod" pair
                            if k8sdeployment.pod_belongs_to_service(pod, service):
                                groups.write(",bucket=set_field:{pod_ip}->nw_dst,set_field:{target_port}->{protocol}_dst,resubmit(,4)".format(
                                    pod_ip=pod.ip_address, target_port=port.target, protocol=port.protocol.lower()))

                        groups.write("\n")
                        group_id += 1

            # catch rule for TABLE 3
            flows.write("table=3,priority=1,ip,actions=goto_table:4\n")

            # TABLE 4 - decide to switch or route
            # local POD: switch
            flows.write("table=4,priority=100,ip,nw_dst={pod_cidr},actions=goto_table:5\n".format(pod_cidr=node.pod_cidr))
            # remote POD: route TODO: 0x3f->tun_id ???
            flows.write("table=4,priority=1,ip,actions=set_field:0x3f->tun_id,goto_table:6\n".format())

            # TABLE 5 - swtiching rules
            for pod in pod_list.values():
                if pod.node_name == node.name and pod.node_ip != pod.ip_address:
                    flows.write(
                        "table=5,priority=110,in_port={outport},ip,nw_dst={pod_ip},actions=set_field:{mac_address}->eth_dst,output:in_port\n".format(
                            pod_ip=pod.ip_address, mac_address=ip2mac(pod.ip_address), outport=last_octet(pod.ip_address)))
                    flows.write(
                        "table=5,priority=100,ip,nw_dst={pod_ip},actions=set_field:{mac_address}->eth_dst,output:{outport}\n".format(
                            pod_ip=pod.ip_address, mac_address=ip2mac(pod.ip_address), outport=last_octet(pod.ip_address)))

            # TABLE 6 - routing rules
            for remote_node in node_list.values():
                if node.name != remote_node.name: # for local noce we do not need routing
                    flows.write(
                        "table=6,priority=100,ip,nw_dst={pod_cidr},actions=set_field:{tunnel_ip}->tun_dst,output:1\n".format(
                            pod_cidr=remote_node.pod_cidr, tunnel_ip=remote_node.tunnel_ip))

            # TABLE 7 - MAC learning --> No longer needed!!
            #flows.write("table=7,priority=1,ip,actions=normal\n")



def last_octet(ip_address):
    last = ip_address.split(".")[3]
    return last


def pod_cidr_to_node_gw(ip_address):
    first_three_octet = ip_address.split(".")[:3]
    return ".".join(first_three_octet) + "." + "1"


def get_diff_files(old, new, rn):
    update_ruleset = {}

    with open(old, 'r') as file1:
        with open(new, 'r') as file2:
            f = file1.read().splitlines()
            f2 = file2.read().splitlines()

    file_type = old.split(".")[-1]
    #print(old + " vs. " + new + ": " + file_type)

    if(file_type == "groups"):
        old_only = {} # (key, value): (group_id, rule)
        new_only = {} # (key, value): (group_id, rule)

        for line in set(f).difference(f2):
            if line != "":
                group_id = re.findall("group_id=([0-9]+),",str(line))[0]
                old_only[group_id] = line

        for line in set(f2).difference(f):
            if line != "":
                group_id = re.findall("group_id=([0-9]+),",str(line))[0]
                new_only[group_id] = line

        toDEL = set(old_only.keys()) - set(new_only.keys())
        toMOD = set(old_only.keys()).intersection(set(new_only.keys()))
        toADD = set(new_only.keys()) - set(old_only.keys())

        tmp_list = []
        for i in toDEL:
            rule = old_only[i].split(",")[0]
            #rule = re.sub("priority=[0-9]+,", "" , rule)
            tmp_list.append(rule)
        update_ruleset["-"] = tmp_list

        tmp_list = []
        for i in toMOD:
            tmp_list.append(new_only[i])
        update_ruleset["?"] = tmp_list

        tmp_list = []
        for i in toADD:
            tmp_list.append(new_only[i])
        update_ruleset["+"] = tmp_list
    else:
        tmp_list = []
        for line in set(f).difference(f2):
            if line != "":
                rule = line.split(",action")[0]
                rule = re.sub("priority=[0-9]+,", "" , rule)
                tmp_list.append(rule)
        update_ruleset["-"] = tmp_list

        tmp_list = []
        for line in set(f2).difference(f):
            if line != "":
                tmp_list.append(line)
        update_ruleset["+"] = tmp_list

    pr_log(update_ruleset, rn, file_type)

    return update_ruleset


def pr(update_ruleset):
    for k, v in update_ruleset.items():
        print(k)
        for r in v:
            print(r)


def pr_log(update_ruleset, rn, type):
    fname = "dunlin-util-" + rn + "-" + type
    file = open("log/" + fname,"w")
    for k, v in update_ruleset.items():
        file.write(k + "\n")
        for r in v:
            file.write("\t" + r + "\n")

    file.close()



def update_ovs_rules(node_list, log_num):
    if not os.path.exists("tmp"): # only "config" folder exists
        for node in node_list.values(): # we just install the rules
            group_file = "config" + "/" + node.name + ".groups"
            call([ "ovs-ofctl", "-O openflow13", "add-groups", "tcp:{node_ip}:16633".format(node_ip=node.ip_address), "{g_file}".format(g_file=group_file)])
            flow_file = "config" + "/" + node.name + ".flows"
            call([ "ovs-ofctl", "-O openflow13", "add-flows", "tcp:{node_ip}:16633".format(node_ip=node.ip_address), "{g_file}".format(g_file=flow_file)])
    else: # tmp folder exists, so we need to merge old and new rules
        # file names have to be the same in both folders
        synch_folder_file_names("config", "tmp")

        for node in node_list.values():
            old_group_file = "config" + "/" + node.name + ".groups"
            new_group_file = "tmp" + "/" + node.name + ".groups"
            update_ruleset_list = get_diff_files(old_group_file, new_group_file, log_num)
            for action, rules in update_ruleset_list.items():
                if action == "-": # delete group rule
                    for r in rules:
                        call(["ovs-ofctl", "-O openflow13", "del-groups","tcp:{node_ip}:16633".format(node_ip=node.ip_address), "{g_id}".format(g_id=r)])
                elif action == "?": # add group rule
                    for r in rules:
                        call([ "ovs-ofctl", "-O openflow13", "mod-group", "tcp:{node_ip}:16633".format(node_ip=node.ip_address), "{params}".format(params=r) ])
                else:
                    for r in rules:
                        call([ "ovs-ofctl", "-O openflow13", "add-group", "tcp:{node_ip}:16633".format(node_ip=node.ip_address), "{params}".format(params=r) ])


            old_flow_file = "config" + "/" + node.name + ".flows"
            new_flow_file = "tmp" + "/" + node.name + ".flows"
            update_ruleset_list = get_diff_files(old_flow_file, new_flow_file, log_num)
            for action, rules in update_ruleset_list.items():
                if action == "-":  # delete flow rule
                    for r in rules:
                        call([ "ovs-ofctl", "-O openflow13", "del-flows", "tcp:{node_ip}:16633".format(node_ip=node.ip_address), "{params}".format(params=r) ])
                else:  # add flow rule
                    for r in rules:
                        call([ "ovs-ofctl", "-O openflow13", "add-flow", "tcp:{node_ip}:16633".format(node_ip=node.ip_address), "{params}".format(params=r) ])
            flow_file = "config" + "/" + node.name + ".flows"
            call([ "ovs-ofctl", "-O openflow13", "add-flows", "tcp:{node_ip}:16633".format(node_ip=node.ip_address), "{g_file}".format(g_file=flow_file)])


        # due to the file name synchronization folder have to cleaned
        remove_empty_files("tmp")

        # remove tmp folder, as it is not needed anymore
        shutil.rmtree("config")
        os.rename("tmp", "config")



def delete_tmp_if_exist():
    if os.path.exists("tmp"):
        shutil.rmtree("tmp")

def refresh_config(log_num, init_step):
    print("\t Calling OVS ruleset update")
    node_list = k8sdeployment.get_nodes()
    service_list = k8sdeployment.get_services()
    pod_list = k8sdeployment.get_pods()

    # initialization step called by watcher.py at first run
    if init_step:
        clear_ovs_tables_on_nodes(node_list)
        if os.path.exists("config"):
            shutil.rmtree("config")
        if os.path.exists("log"):
            shutil.rmtree("log")
        os.makedirs("log")

    create_ovs_ruleset_for_each_node(node_list, service_list, pod_list)
    update_ovs_rules(node_list, str(log_num))

    print("\t\t Update is finished!")


if sys.version_info[0] != 3 or sys.version_info[1] < 5:
    print("This script requires Python version 3.5")
    sys.exit(1)

# register exit handler
atexit.register(delete_tmp_if_exist)

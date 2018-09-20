from kubernetes import client, config

config.load_kube_config("/etc/kubernetes/admin.conf")
v1 = client.CoreV1Api()

class Port:
    def __init__(self, protocol, source, target):
        self.protocol = protocol
        self.source = source
        self.target = target


class Service:
    def __init__(self, name, cluster_ip, selectors, port_list):
        self.name = name
        self.cluster_ip = cluster_ip
        self.selectors = selectors
        self.ports = port_list


class Pod:
    def __init__(self, name, node_name, node_ip, ip_address, labels):
        self.name = name
        self.node_name = node_name
        self.node_ip = node_ip
        self.ip_address = ip_address
        self.labels = labels

    def is_stable(self): # when multiple pods are going down, it can happen that the code reads an unstable pod
        return self.name is not None\
               and self.node_name is not None\
               and self.node_ip is not None\
               and self.ip_address is not None\
               and self.labels is not None


class Node:
    def __init__(self, name, ip_address, pod_cidr, type, tunnel_ip):
        self.name = name
        self.ip_address = ip_address
        self.pod_cidr = pod_cidr
        self.type = type
        self.tunnel_ip = tunnel_ip


def get_services():
    service_list = {}
    for i in v1.list_service_for_all_namespaces().items:
        name = i.metadata.name
        cluster_ip = i.spec.cluster_ip
        selectors = i.spec.selector
        port_list = []
        for j in i.spec.ports:
            port = Port(j.protocol, j.port, j.target_port)
            port_list.append(port)

        service = Service(name, cluster_ip, selectors, port_list)
        service_list[name] = service

    return service_list


def get_nodes():
    node_list = {}
    for i in v1.list_node().items:
        name = i.metadata.name
        ip_address = i.status.addresses[0].address #internalIP = public-ip
        pod_cidr = "10.244." + ip_address.split(".")[-1] + ".0/24";
        #pod_cidr = i.spec.pod_cidr
        tunnel_ip = ip_address #TODO: for control / data plane separation need some logic here

        if "master" in str(i.metadata.labels):
            type = "master"
        else:
            type = "worker"

        node = Node(name, ip_address, pod_cidr, type, tunnel_ip)
        node_list[name] = node

    return node_list


def get_pods():
    pod_list = {}
    for i in v1.list_pod_for_all_namespaces(watch=False).items:
        name = i.metadata.name
        node_name = i.spec.node_name
        node_ip = i.status.host_ip
        ip_address = i.status.pod_ip
        labels = i.metadata.labels
        pod = Pod(name, node_name, node_ip, ip_address, labels)
        if pod.is_stable(): # we only want to deal with stable pods
            pod_list[name] = pod

    return pod_list


def print_services(service_list):
    for k, v in service_list.items():
        print(v.name)
        print(v.cluster_ip)
        print(v.selectors)
        for p in v.ports:
            print("%s\t%s\t%s" % (p.protocol, p.source, p.target))
        print


def print_pods(pod_list):
    for k, v in pod_list.items():
        print(v.name)
        print(v.node_name)
        print(v.node_ip)
        print(v.ip_address)
        print(v.labels)
        print(v.is_stable())
        print


def print_nodes(node_list):
   for k, v in node_list.items():
        print(v.name)
        print(v.ip_address)
        print(v.pod_cidr)
        print(v.type)
        print(v.tunnel_ip)
        print


def pod_belongs_to_service(pod, service):
    p = pod.labels
    s = service.selectors

    if p is None or s is None:
        return False

    return len(set(s.items()) & set(p.items())) == len(s)


def service_without_pod_backend(service, pod_list):
    for pod in pod_list:
        if(pod_belongs_to_service(pod, service)):
            return False
    return True


def get_master_node_name(node_list):
    for node in node_list.values():
        if node.type == "master":
            return node.name

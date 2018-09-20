from kubernetes import client, config, watch
import k8sovsutil_shift
import os

print("Initial config for setting OVS rules")
log_num = 0
k8sovsutil_shift.refresh_config(log_num, True)

#print(call(["cp", "/etc/kubernetes/admin.conf", "/root/.kube/config"]))
config.load_kube_config('/etc/kubernetes/admin.conf')

v1 = client.CoreV1Api()

w = watch.Watch()
#for event in w.stream(v1.list_pod_for_all_namespaces):
for event in w.stream(v1.list_namespaced_pod, "default"):
    if event['type'] == "MODIFIED" and event['object'].status.phase == "Running" and not event['object'].metadata.deletion_timestamp:
        print("ADDED %s\t%s" % (event['object'].status.pod_ip, event['object'].metadata.name), event['object'].metadata.deletion_timestamp)
        log_num += 1
        k8sovsutil_shift.refresh_config(log_num, False)
    if event['type'] == "DELETED":
        print("DELETED %s\t%s" % (event['object'].status.pod_ip, event['object'].metadata.name), event['object'].metadata.deletion_timestamp)
        log_num += 1
        k8sovsutil_shift.refresh_config(log_num, False)
    #print("Event: %s %s %s" % (event['type'], event['object'].kind, event['object'].metadata.name))
    #print("Event: %s\t %s\t %s" % (event['object'].status.phase, event['object'].metadata.name, event['object'].status.pod_ip))
    #k8sovsshiftutil.refresh_config()

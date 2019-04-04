import k8sovsutil_shift
import os
import time

print("Initial config for setting OVS rules")
log_num = 0
k8sovsutil_shift.refresh_config(log_num, True)

while True:
    log_num += 1
    k8sovsutil_shift.refresh_config(log_num, False)
    time.sleep(1)

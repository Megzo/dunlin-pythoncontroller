FROM ubuntu:16.04
RUN apt-get update
RUN apt-get install python3 -y
RUN apt-get install python3-pip -y
RUN apt-get install openvswitch-switch -y
RUN pip3 install --upgrade pip
RUN pip3 install netconf
RUN pip3 install kubernetes
WORKDIR /root

COPY k8sdeployment.py .
COPY k8sovsutil_shift.py .
COPY controller.py .
ENTRYPOINT ["python3", "controller.py"] 

# Python controller for Dunlin Plugin 
This controller was created in order to further popularize Open vSwitch based Kubernetes cluster networking. This is an MVP version in Python, in later versions we will use GO for the same purpose.

This simple Python controller connects to the Kubernetes API, reads information of PODs, Services and Nodes, and install
appropriate OpenFlow rules to the OVS switches running on every K8S nodes so that every POD can reach each other in the cluster.

To use the Dunlin Plugin in your Kubernetes cluster, before the installation of the network plugin (refer to step #3 at https://kubernetes.io/docs/setup/independent/create-cluster-kubeadm/) install Open vSwitch on every node using the following command:

    $ sudo apt install openvswitch-switch
    
You can veryfy that OVS is up and running by the following command:

    $ sudo ovs-vsctl show
    
Then, you can install the Dunlin Plugin with the following Kubernetes command:

    $ kubectl apply -f https://dunlin.io/dunlin.yaml
    
    

# PESS: Progressive Embedding of Security Services

PESS is a solution to provision security services in softwarised networks, where network functions can be dynamically deployed on commodity hardware following the NFV paradigm, and the network is controlled using SDN technologies. In this context, the security services are defined as sequences (chains) of Virtual Security Network Functions (VSNFs), i.e. as software functions (e.g., Snort, Suricata, OpenDPI, etc.), which are provisioned in the network infrastructure according to the specific Quality of Service (QoS) needs of user applications and the security policies defined by the Telecom Service Provider (TSP). TSP's security policies (given as an input to PESS) include: the kind of VSNFs (e.g., firewall, Intrusion Prevention System (IPS), etc.) that should be deployed for a specific class of applications, their order (e.g., firewall first, then an IPS, etc.), and more (e.g., a parental control should be installed close to the user's premises). 

The output of PESS is the mapping of the VSNFs onto the physical network (position of the VSNFs and one or more paths between them) and an updated model of the physical network taking into account the resources used to provision the service. The updated model is used as an input for the next request. In this regard, PESS supports service provisioning in dynamic network scenarios, where the service requests are not known in advance. In contrast, advance knowledge of service requests is assumed by the majority of related works. 

PESS has been evaluated on real-word network topologies such as GARR (https://www.garr.it/it/documenti/26-leaflet-garr-network) and Stanford (https://www.usenix.org/system/files/conference/nsdi12/nsdi12-final8.pdf). Its performance in terms of quality of the security service provisioning solutions (deviation from optimality) and scalability are available in the following research paper:

R. Doriguzzi-Corin, S. Scott-Hayward, D. Siracusa, M. Savi, and E. Salvadori, “Dynamic and Application-Aware Provisioning of Chained Virtual Security Network Functions,” in *IEEE Transactions on Network and Service Management*, vol. 17, no. 1, pp. 294–307, 2020, doi:10.1109/TNSM.2019.2941128.

This repository collects the Python scripts developed to implement and evaluate the PESS concept. It is organised as follows:

| File                   | Description                                                  |
| ---------------------- | ------------------------------------------------------------ |
| solver.py              | Main script. It implements a set of routines for reproducing the tests described in the paper |
| heuristic_algorithm.py | Implementation of the PESS heuristic. The main method is *embed_service*, which is called to provision a given service onto the network. It also takes care of managing the residual network and computing resources. See also *solver.py* for more details. |
| network.py             | Script that generates the physical network topology. It can use  a pre-defined network model, or generate a random network. Two network models are available in the *data* folder, others can be implemented following the same schema (see below for more details). Random networks are generated using the Barabási-Albert model (which can be changed in the code, if needed) at different sizes (number of nodes) and degrees. |
| virtual_network.py     | Implements different methods for the random generation of security services. It takes an instance of the physical network as input (which is used to select the end-points of the service). It also defines the VSNFs, each with its computing requirements and properties, as described in the paper. |
| utils_functions.py     | Set of functions used in the other script to save the results, show the network topology, etc. |



## Installation

PESS has been implemented in Python v2.7 plus library NetworkX (https://networkx.org/) to handle the network topologies.

PESS requires the installation of a few Python tools and libraries. This can be done by using the ```conda``` software environment (https://docs.conda.io/projects/conda/en/latest/).
We suggest the installation of ```miniconda```, a light version of ```conda```. ```miniconda``` is available for MS Windows, MacOSX and Linux and can be installed by following the guidelines available at https://docs.conda.io/en/latest/miniconda.html#. 

In a Linux OS, execute the following command and follow the on-screen instructions:

```
bash Miniconda3-latest-Linux-x86_64.sh
```

Then create a new ```conda``` environment (called ```myenv```) based on Python 2.7 and including the required packages:

```
conda create -n myenv python=2.7 numpy scipy matplotlib networkx=1.11 decorator==4.4.2
```

Activate the new ```myenv``` environment:

```
conda activate myenv
```

For the sake of simplicity, we omit the command prompt ```(myenv)$``` in the following example commands in this README.   ```(myenv)$``` indicates that we are working inside the ```myenv``` execution environment, which provides all the required libraries and tools. If the command prompt is not visible, re-activate the environment as explained above.

## Network models

Two real-world network models are provided with the code: the topology of the Italian national computer network for universities and research (GARR, https://www.garr.it/en/infrastructures/network-infrastructure/our-network) and the topology of the Stanford backbone (www.usenix.org/system/files/conference/nsdi12/nsdi12-final8.pdf). The models are provided in the form of text files formatted as follows:

- Number of nodes and links in the first line 
- List of nodes, e.g. ```MI2 45.4667984 9.0961034 1 0```, where the first field is the node ID, followed by the node's coordinates (latitude and longitude), region ID and a flag that indicated whether the node is a *veto* node or not. Latitude and longitude are used to compute the link propagation delay between two nodes. If longitude and latitude are equal to zero, the resulting propagation delay will be zero. This also affects the representation of the topology map (see option ```-d``` below), which will show all the nodes in one single point overlapping with each other.
- List of links, e.g. ```BN NA6 10000000000```, where the first two fields are the endpoints of the link, while the third in the bandwidth expressed in ```bits/sec```. Note that the endpoints of the link must be defined in the list of nodes above.

Of course, other topologies can be used, provided that their specification follows the schema detailed above.

## Simulations

The methods implemented in ```solver.py``` allow the user to evaluate the PESS heuristic in terms of scalability and to compare it against an ''application-agnostic'' approach on real-world and random topologies. Referring to the paper mentioned above, these experiments are described in Sections VII-C and VII-D. 

Script ```solver.py``` accepts the following parameters:

- ```-e, ``` ```--experiment```: Identifier of the experiment to run: 1=baseline_comparison_random, 2=baseline_comparison_garr, 3=baseline_comparison_stanford, 4=scalability, 5=scalability_region (more details are provided below);
- ```-s, ``` ```--size ```: Size of the random networks (in terms of number of nodes);
- ```-t, ``` ```--topology ```: Topology specification file. GARR and Stanford topology files are provided in folder ```data```. If not indicated, a random topology will be generated and used instead;
- ```-p```, ```--print_output ```: Print the output of the process. It can significantly slow down the execution;
- ```-d```, ```--display_topology ```: Display the topology used for the experiment.

With option ```--experiment```, one can select the experiment to run. Below, we provide a brief description of each experiment (more details are available in the paper).

### PESS vs application-agnostic provisioning

This test aims at comparing PESS against the baseline approach, in which the provisioning algorithm does not consider the specific security and QoS requirements of the applications.  In the paper, the comparison is done in terms of blocking probability, consumption of computing resources, end-to-end latency of the chains and number of active services in the network. Such metrics can be obtained with the output of the test saved as text file(s).

The test executes two experiments in parallel using two identical copies of the same physical network graph. At each iteration, a service request with application-specific QoS and security requirements is generated. In *Experiment 1*, the security service is provisioned on one copy of the network with the PESS heuristic. In *Experiment 2*, the service is provisioned on the second copy of the network by simulating the baseline approach, where two application-agnostic chains of VSNFs (one for each direction of the traffic) are applied to the user traffic to fulfill all the security requirements regardless of the specific needs of the applications. At the end of each iteration, the two copies of the network are updated according to the resources consumed by the respective provisioning approach.

The comparison can be performed in three different scenarios: the GARR Italian computer network, the Stanford backbone topology, and random networks (Barabási-Albert model). Dependently on the scenario, the test can be started as follow:

```
# python2 solver.py -p -s 20 -e 1
# python2 solver.py -p -t data/garr-topology -e 2
# python2 solver.py -p -t data/stanford-topology -e 3
```

As described above, option ```-e=1,2 or 3``` tells the script to execute the comparison between PESS and the baseline on a random topology,  the GARR network or  the Stanford backbone topology respectively. Option ```-s 20``` specifies the number of nodes in the random networks, while option ```-p``` enables the script's output on the terminal.

### Scalability

The goal of the scalability test is to show the performance of PESS at various network sizes (10,100,250,500,750 and 1000 nodes).  The two tests described in the paper (Section VII-D) are implemented in ```solver.py``` and can be executed by running one of the two commands:

```
# python2 solver.py -e 4
# python2 solver.py -t data/garr-topology -e 5
```

In experiment number 4 (first command), the network degree of the random topology is set to 1, 3 and 5. In the experiment number 5, the network degree is set to 5 (worst case scenario), while the region size is varied starting from 1 node, to 10%, 25% or 50% of the entire network. For comparison with a real-world scenario, here we also load the GARR topology, whose border region consists of 5 nodes out of 46.  

### Test results

The results of the tests are saved as text files in a folder named ```log```, which is created at the first execution.  Such files are named using the following schema:  PARAMETER-EXPERIMENT-DATE-TIME-#NETWORK_SIZE. Each line in these files is the report of a successful service provisioning. The list of rejected requests is instead saved in another file with the same name plus suffix ```-infeasible```. Below are some examples:

```
1000.0-GARR-PESS-2021-03-12-23-01-03-#20.log (load=1000, experiment=GARR-PESS, datetime=2021-03-12-23-01-03, nodes=20)
1000.0-GARR-PESS-2021-03-12-23-01-03-#20-infeasible.log
8000.0-GARR-BASELINE-2021-03-12-23-03-14-#26.log (load=8000, experiment=GARR-BASELINE, datetime=2021-03-12-23-03-14, nodes=26)
8000.0-GARR-BASELINE-2021-03-12-23-03-14-#26-infeasible.log
3-SCALABILITY-2021-03-15-12-32-41.log (network degree=3, experiment=SCALABILITY, datetime=22021-03-15-12-32-41, nodes=26)
```

PARAMETER is the most representative parameter of the experiment.  In the case of the comparison with the application-agnostic approach, *Load*  is used to indicate the network load expressed in Erlang configured for the experiment (between 1000 and 20000). For the scalability experiments, the network degree and the region size are used instead.

Each line summarises the outcome of provisioning a security service request with PESS and contains the following information:

| Field                  | Description                                                  |
| ---------------------- | ------------------------------------------------------------ |
| **ID**                 | Service identifier. In the tests described above, this is an incremental number starting from 1 |
| **Nodes**              | Number of nodes in the physical network topology used for the test |
| **Edges**              | Number of edges in the physical network topology used for the test |
| **Chains**             | Number of chains in the service                              |
| **VSNFs**              | Total number of VSNFs in the service                         |
| **Total cost**         | Embedding cost as computed using the objective function (3) in the paper |
| **CPU cost**           | Embedding CPU cost (rightmost summation in equation (3) in the paper) |
| **Network cost**       | Embedding bandwidth cost (leftmost summation in equation (3) in the paper) |
| **Consumed CPU**       | Percentage of the computing resources consumed by all the successfully provisioned services, with respect to the amount of computing resources available in the network |
| **Consumed Bandwidth** | Percentage of the bandwidth consumed by all the successfully provisioned services, with respect to the amount of bandwidth available in the network |
| **Used CPU region**    | Percentage of the computing resources consumed by all the successfully provisioned services, with respect to the amount of computing resources available in a region |
| **Average Latency**    | Estimated average latency of service's chains, as computed in equation (14) in the paper |
| **Load**               | Load of the network, i.e. number of active services in the network |
| **Time**               | Embedding time                                               |
| **Result**             | Output of PESS. 0 means successful embedding. A negative number indicates that the service request has been rejected: -1 means that PESS was not able to find a path between the two endpoints with enough resources, -2 means that although at least one path with enough resources has been found, using that path would compromise the end-to-end latency of operational chains (equation (19) in the paper).  In the case of successful embedding, one can also select to save the full solution instead of just 0. This can be done by removing ```0#``` after ```=``` from the following line in ```heuristic_algorithm.py```: ```solution_string = 0#self.solution_to_string(vnf_node_mapping, vlink_edge_mapping)``` |



## Acknowledgements

If you are using PESS's code for a scientific research, please cite the related paper in your manuscript as follows:

R. Doriguzzi-Corin, S. Scott-Hayward, D. Siracusa, M. Savi, and E. Salvadori, “Dynamic and Application-Aware Provisioning of Chained Virtual Security Network Functions,” in *IEEE Transactions on Network and Service Management*, vol. 17, no. 1, pp. 294–307, 2020, doi:10.1109/TNSM.2019.2941128.

## License

The code is released under the Apache License, Version 2.0.


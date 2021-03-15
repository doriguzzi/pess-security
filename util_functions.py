# Copyright (c) 2020 @ FBK - Fondazione Bruno Kessler
# Author: Roberto Doriguzzi-Corin
# Project: PESS: Progressive Embedding of Security Services
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from math import cos, asin, sqrt,exp, log
import random
import networkx as nx
import matplotlib.pyplot as plt
import os

lat_coeff=0.001
delta = 0.001

SEED = 0
GHz = 1000000000
Mbit = 1000000
SECURITY_VNFS = 13 #like listed in the paper (table in the evaluation)
MAX_CHAINS = 5
MAX_VNFS_PER_CHAIN = 3
MIN_LATENCY = 0.060 # seconds
MAX_LATENCY = 0.400 # seconds
MIN_CPU = 5
MAX_CPU = 32
MIN_PACKET_SIZE = 64*8 # minimum packet size in bits
MAX_PACKET_SIZE = 1500*8 # maximum packet size in bits
INTERNET_LATENCY = 0.010 #latency from the network border to Internet (e.g. online gaming server) in seconds
MIN_BANDWIDTH = 100*1000 # bits per second
MAX_BANDWIDTH = 5*Mbit # bits per second
CPU_UNITS_PER_LINK = 1*32*2100*1000*1000 # servers * cores * frequency (cycles per second)

QUEUING_DELAY_BOUND = 0.00008  # maximum queuing delay that can occur  at a switch port (80us)
SWITCH_QUEUING_DELAY = round(QUEUING_DELAY_BOUND*2,6) # queuing delay experienced by a packet when traversing a switch (2 ports)

def distance(lat1, lon1, lat2, lon2):
    p = 0.017453292519943295     #Pi/180
    a = 0.5 - cos((lat2 - lat1) * p)/2 + cos(lat1 * p) * cos(lat2 * p) * (1 - cos((lon2 - lon1) * p)) / 2
    return 12742 * asin(sqrt(a)) #2*R*asin...

random.seed(SEED)
def random_exponential(lambd):
    return -log(1.0 - random.random())/lambd

def sigmoid(x):
    return 1/(1+exp(-1000*(x-1)))


def link_latency(distance):
    propagation_delay = (float(distance)/299792)*1.5 #(km/(km/s))*(refraction index)*1000 -> latency in seconds
    #queuing_delay = 2*DATACENTER_TOTAL_QUEUING_DELAY # the packet exits one datacenter and enters the next one
    return round(propagation_delay,6)

def get_node_coordinates(nodes,label):
    for node in nodes:
        if node.label == label:
            return node.x, node.y

def get_node_index(nodes,label):
    for node in nodes:
        if nodes[node]['label'] == label:
            return node

# computation of the processing delay as: L(c,i,u) = coeff1(i)*B(c) + coeff2(i)*Gu(u) + coeff3(i)*Gi(i) + Gu(u)/Gir(i)
def vnf_processing_delay(pn, c, i, u):
    B = c[0]['bandwidth']  # bandwidth of the chain (bits/sec)
    S = c[0]['packet_size']  # maximum packet size of the chain (bits/pkt)
    Gu = float(c[0][u]['cpu'])  # CPU requirements of u (cycles/bit)
    Gi = float(pn.nodes[i]['cpu'])  # CPU of node i
    Gir = float(pn.nodes[i]['residual_cpu'])  # residual CPU of node i
    if Gu == 0:
        return 0

    #print "old_chains_overhead: ", old_chains_overhead

    L = (Gu*S) / ((Gir - B*Gu) + delta) # in sec/pkt
    #print "latency: ", L
    return L

def draw_graph(nodes, edges, graph_layout='shell',
               node_size=300, node_color='gray', node_alpha=0.3,
               node_text_size=8,
               edge_color='blue', edge_alpha=0.3, edge_tickness=1,
               text_font='sans-serif'):

    # create networkx graph
    G=nx.Graph()
    # add edges with (bandwidth,latency) weights
    # we esclude fake edges
    for edge in edges:
        if edge[0] != edge[1]:
            G.add_edge(edges[edge]['label'][0], edges[edge]['label'][1],weight=(edges[edge]['bandwidth'],edges[edge]['latency']))

    # assigning the weights to the nodes: CPU core and RAM megabytes
    for node in nodes:
        #G.node[node.label]['weight'] = node.capacity
        G.node[nodes[node]['label']]['label'] = nodes[node]['label']
        G.node[nodes[node]['label']]['pos'] = (nodes[node]['lon'],nodes[node]['lat'])

    # these are different layouts for the network you may try
    # shell seems to work best
    if graph_layout == 'spring':
        graph_pos=nx.spring_layout(G)
    elif graph_layout == 'spectral':
        graph_pos=nx.spectral_layout(G)
    elif graph_layout == 'random':
        graph_pos=nx.random_layout(G)
    else:
        graph_pos=nx.shell_layout(G)

    # draw graph
    node_labels = nx.get_node_attributes(G, 'label')
    node_pos = nx.get_node_attributes(G,'pos')
    edge_labels = nx.get_edge_attributes(G, 'weight')
    nx.draw_networkx_nodes(G,pos=node_pos,node_size=node_size,
                           alpha=node_alpha, node_color=node_color)
    nx.draw_networkx_edges(G,node_pos,width=edge_tickness,
                           alpha=edge_alpha,edge_color=edge_color)
    nx.draw_networkx_labels(G, node_pos,font_size=node_text_size,
                            font_family=text_font,labels=node_labels)
    nx.draw_networkx_edge_labels(G, node_pos, edge_labels=edge_labels,font_size=node_text_size,
                                 label_pos=0.5)


    # show graph
    plt.show(block=True)



def save_result(filename,service_id,nodes,edges, chains, vnfs, embedding_cost, cpu_cost, bandwidth_cost, consumed_cpu, consumed_bandwidth,consumed_region_cpu, average_latency, nr_services, exec_time, solution_string):
    if os.path.isdir('./log') is False:
        os.mkdir("log")

    file = open("log/" + filename+".log", "a")
    file.write(str(service_id) + " " + str(nodes) + " " + str(edges) + " " + str(chains) + " " + str(vnfs) + " " + str(embedding_cost) + " " + str(cpu_cost) + " " + str(bandwidth_cost) + " " \
               + str(consumed_cpu) + " " + str(consumed_bandwidth) + " " + str(consumed_region_cpu) + " " + str(average_latency) + " " + str(nr_services) + " " + str(exec_time) + " " + str(solution_string) + '\n')
    file.close()


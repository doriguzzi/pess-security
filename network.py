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

from collections import OrderedDict
from util_functions import *
import copy
import random

random.seed(SEED)

class physical_network:
    def __init__(self, lines=None, parts=None, size=None,region_perc=0,degree=2, local_network_tiers=3, unlimited_bandwidth=False):
        self.nodes = OrderedDict()
        self.edges = OrderedDict()
        self.chain_map = {}
        self.service_map = {}
        self.region_cpu_map = {}
        self.chain_index = 0
        self.cpu_capacity = 0
        self.max_node_cpu = 0
        self.bandwidth_capacity = 0
        self.distance_map = {}
        self.neighbors_map = {}
        self.all_pairs_path = {}
        self.nxGraph = None
        self.unlimited_bandwidth = unlimited_bandwidth
        if lines is None or parts is None:
            self.node_count = 0
            self.physical_edge_count = 0
            # the loop continue until init_random generates a single-component network
            while self.init_random(size,region_perc,degree) is False:
                continue
        else:
            self.node_count = int(parts[0])
            self.physical_edge_count = int(parts[1])
            self.init_from_file(lines)
            # generation of border and veto regions

        self.veto_region = self.get_veto_region()
        self.border_region = self.get_border_region()
        self.edge_count = len(self.edges)
        self.local_network_tiers=local_network_tiers

    def init_from_file(self,lines):
        # adding nodes
        for i in range(1, self.node_count + 1):
            line = lines[i]
            parts = line.split()
            self.nodes[i - 1] = {'label': str(parts[0]), 'lat': float(parts[1]), 'lon': float(parts[2]), 'region': float(parts[3]), 'veto': float(parts[4]), 'cpu': 0, 'residual_cpu': 0, 'allocated_cpu_cycles' : 0}

        # adding real edges
        for i in range(self.node_count + 1, self.node_count + self.physical_edge_count + 1):
            line = lines[i]
            parts = line.split()

            node0_index = get_node_index(self.nodes, str(parts[0]))
            node1_index = get_node_index(self.nodes, str(parts[1]))
            self.edges[(node0_index, node1_index)] = {'bandwidth': int(parts[2]) if self.unlimited_bandwidth is False else float('inf'),
                                                 'residual_bandwidth': int(parts[2]) if self.unlimited_bandwidth is False else float('inf'),
                                                 'label': (str(parts[0]), str(parts[1])),
                                                 'type' : 'physical',
                                                 'latency': link_latency(distance(
                                                     self.nodes[node0_index]['lat'],
                                                     self.nodes[node0_index]['lon'],
                                                     self.nodes[node1_index]['lat'],
                                                     self.nodes[node1_index]['lon']))}
            self.edges[(node1_index, node0_index)] = {'bandwidth': int(parts[2]) if self.unlimited_bandwidth is False else float('inf'),
                                                 'residual_bandwidth': int(parts[2]) if self.unlimited_bandwidth is False else float('inf'),
                                                 'label': (str(parts[1]), str(parts[0])),
                                                 'type': 'physical',
                                                 'latency': link_latency(distance(
                                                     self.nodes[node0_index]['lat'],
                                                     self.nodes[node0_index]['lon'],
                                                     self.nodes[node1_index]['lat'],
                                                     self.nodes[node1_index]['lon']))}
            self.bandwidth_capacity += 2*int(parts[2]) if self.unlimited_bandwidth is False else float('inf')

            # node capabilities depend on the number of incident links
            self.nodes[node0_index]['cpu'] += CPU_UNITS_PER_LINK
            if self.nodes[node0_index]['cpu'] > self.max_node_cpu:
                self.max_node_cpu = self.nodes[node0_index]['cpu']
            self.nodes[node1_index]['cpu'] += CPU_UNITS_PER_LINK
            if self.nodes[node1_index]['cpu'] > self.max_node_cpu:
                self.max_node_cpu = self.nodes[node1_index]['cpu']
            self.nodes[node0_index]['residual_cpu'] += CPU_UNITS_PER_LINK
            self.nodes[node1_index]['residual_cpu'] += CPU_UNITS_PER_LINK
            self.cpu_capacity += 2*CPU_UNITS_PER_LINK

        # adding local fake edges with "infinite" bandwidth and 0 latency
        # be careful!! These links must always stay after the physical ones in the list (constraint 15 in the gurobi model)
        for node in self.nodes:
            self.edges[(node, node)] = {'bandwidth': float('inf'), 'residual_bandwidth': float('inf'),
                                        'label': (self.nodes[node]['label'], self.nodes[node]['label']),
                                        'type' : 'loop','latency': 0}


        self.nxGraph = self.generate_graph(self.nodes,self.edges)
        #self.set_graph_links_weights(self.nxGraph, self.edges)
        #self.all_pairs_path = nx.all_pairs_dijkstra_path(self.nxGraph,weight='weight')
        self.generate_neighbours()


    def init_random(self,size,region_perc=0,degree=2):

        #self.nxGraph = nx.gnp_random_graph(size, 0.01)
        self.nxGraph = nx.barabasi_albert_graph(size, degree) #scale free network model
        if nx.is_connected(self.nxGraph) is False:
            return False

        self.node_count = len(self.nxGraph.nodes())
        self.physical_edge_count = len(self.nxGraph.edges())
        if region_perc > 0:
            region_size=float(region_perc*size)/100 #region size is the % of region nodes in the network
            region_node_index=int(size/float(region_size))
        else:
            region_node_index = 0

        # node properties: 10% of region nodes
        for i in range(self.node_count):
            self.neighbors_map[i] = self.nxGraph.neighbors(i)
            neighbors = len(list(self.neighbors_map[i]))
            self.nodes[i] = {'label': "N" + str(i), 'lat': random.randint(0,1000), 'lon': random.randint(0,1000),
                        'region': 0 if region_node_index == 0 else 1 if i%region_node_index == 0 else 0, # 1 region node every "region_node_index". In the GARR network region_node_index = ~11
                        'veto': 0,
                        'cpu': neighbors * CPU_UNITS_PER_LINK,
                        'residual_cpu': neighbors * CPU_UNITS_PER_LINK,
                        'allocated_cpu_cycles' : 0}
            self.cpu_capacity += neighbors * CPU_UNITS_PER_LINK

        # adding real edges
        for edge in self.nxGraph.edges():
            if self.unlimited_bandwidth == False:
                bandwidth = random.randrange(1000000000,100000000000,10000000000)
            else:
                bandwidth = float('inf')
            latency = link_latency(random.randint(10,100)) #random distance between nodes
            self.edges[(edge[0],edge[1])] = {'bandwidth': bandwidth,
                                  'residual_bandwidth': bandwidth,
                                  'label': ("N" + str(edge[0]), "N" + str(edge[1])),
                                  'type': 'physical',
                                  'latency': latency}
            self.edges[(edge[1], edge[0])] = {'bandwidth': bandwidth,
                                              'residual_bandwidth': bandwidth,
                                              'label': ("N" + str(edge[1]), "N" + str(edge[0])),
                                              'type': 'physical',
                                              'latency': latency}
            self.bandwidth_capacity += 2 * bandwidth

        # adding local fake edges with "infinite" bandwidth and 0 latency
        for node in self.nodes:
            self.edges[(node, node)] = {'bandwidth': float('inf'), 'residual_bandwidth': float('inf'),
                                        'label': (self.nodes[node]['label'], self.nodes[node]['label']),
                                        'type': 'loop', 'latency': 0}

        #self.set_graph_links_weights(self.nxGraph, self.edges)
        #self.all_pairs_path = nx.all_pairs_dijkstra_path(self.nxGraph,weight='weight')
        return True

    # method to assign specific bandwidth resources to the physical network
    def set_bandwidth_resources(self,bandwidth,coeff):
        for edge in self.edges:
            if self.edges[edge]['type'] is 'physical':
                new_bandwidth = int(random.uniform(bandwidth, bandwidth+bandwidth*coeff))
                self.edges[(edge[0],edge[1])]['bandwidth'] = new_bandwidth
                self.edges[(edge[1], edge[0])]['bandwidth'] = new_bandwidth
                self.edges[(edge[0], edge[1])]['residual_bandwidth'] = new_bandwidth
                self.edges[(edge[1], edge[0])]['residual_bandwidth'] = new_bandwidth

        # we need this second loop to update the bandwidth capacity
        self.bandwidth_capacity = 0
        for edge in self.edges.itervalues():
            if edge['type'] == 'physical':
                self.bandwidth_capacity += edge['bandwidth']

        # method to assign specific bandwidth resources to the physical network

    def set_exact_bandwidth_resources(self, new_bandwidth):
        for edge in self.edges:
            if self.edges[edge]['type'] is 'physical':
                self.edges[(edge[0], edge[1])]['bandwidth'] = new_bandwidth
                self.edges[(edge[1], edge[0])]['bandwidth'] = new_bandwidth
                self.edges[(edge[0], edge[1])]['residual_bandwidth'] = new_bandwidth
                self.edges[(edge[1], edge[0])]['residual_bandwidth'] = new_bandwidth

        # we need this second loop to update the bandwidth capacity
        self.bandwidth_capacity = 0
        for edge in self.edges.itervalues():
            if edge['type'] == 'physical':
                self.bandwidth_capacity += edge['bandwidth']

    def set_average_bandwidth_resources(self, bandwidth_average):
        bandwidth_delta = bandwidth_average * 0.10  # 10%
        for edge in self.edges:
            if self.edges[edge]['type'] is 'physical':
                new_bandwidth = int(random.uniform(bandwidth_average-bandwidth_delta, bandwidth_average+bandwidth_delta))
                self.edges[(edge[0], edge[1])]['bandwidth'] = new_bandwidth
                self.edges[(edge[1], edge[0])]['bandwidth'] = new_bandwidth
                self.edges[(edge[0], edge[1])]['residual_bandwidth'] = new_bandwidth
                self.edges[(edge[1], edge[0])]['residual_bandwidth'] = new_bandwidth

        # we need this second loop to update the bandwidth capacity
        self.bandwidth_capacity = 0
        for edge in self.edges.itervalues():
            if edge['type'] == 'physical':
                self.bandwidth_capacity += edge['bandwidth']

    # method to assign specific cpu resources to the physical network
    def set_cpu_resources(self, cpu):
        self.cpu_capacity = 0
        for node in self.nodes.itervalues():
            node['cpu'] = cpu
            node['residual_cpu'] = cpu
            self.cpu_capacity += node['cpu']

    # method to assign cpu resources based on an average target
    def set_average_cpu_resources(self, cpu_average):
        self.cpu_capacity = 0
        cpu_delta = cpu_average*0.10 #10%
        for node in self.nodes.itervalues():
            new_cpu = int(random.uniform(cpu_average-cpu_delta, cpu_average+cpu_delta))
            node['cpu'] = new_cpu
            node['residual_cpu'] = new_cpu
            self.cpu_capacity += node['cpu']

    # method to assign specific cpu resources to the physical network
    def set_exact_cpu_resources(self, new_cpu):
        self.cpu_capacity = 0
        for node in self.nodes.itervalues():
            node['cpu'] = new_cpu
            node['residual_cpu'] = new_cpu
            self.cpu_capacity += node['cpu']

    def reset_residual_resources(self):
        for edge in self.edges.itervalues():
            edge['residual_bandwidth'] = edge['bandwidth']

        for node in self.nodes.itervalues():
            node['residual_cpu'] = node['cpu']

    # generate networkx graph from a network model
    def generate_graph(self,nodes,edges):
        G = nx.Graph()
        for node in nodes.iterkeys():
            G.add_node(node)
        for e_index, edge in edges.iteritems():
            if edge['type'] == 'physical':
                G.add_edge(e_index[0],e_index[1])

        return G

    # distance and neighborood maps. The latter is used in the shortest path algorithm
    def generate_neighbours(self):
        for nodeA in self.nodes:
            self.neighbors_map[nodeA] = []
            for nodeB in self.nodes:
                if nodeB != nodeA and (nodeA, nodeB) in self.edges:
                    self.neighbors_map[nodeA].append(nodeB)

    # get border region
    def get_border_region(self):
        border_region = OrderedDict()
        for node in self.nodes:
            if self.nodes[node]['region'] == 1 and node not in self.veto_region:
                border_region[node] = self.nodes[node]
        return border_region

    # get veto region
    def get_veto_region(self):
        veto_region = OrderedDict()
        for node in self.nodes:
            if self.nodes[node]['veto'] == 1:
                veto_region[node] = self.nodes[node]
        return veto_region

    # generate app node outside the border and the veto region
    def generate_app_node(self):
        app_node_index = random.sample(self.nodes,1)[0]
        border_indexes = self.border_region.keys()
        veto_indexes = self.veto_region.keys()
        while app_node_index in border_indexes or app_node_index in veto_indexes:
            app_node_index = random.sample(self.nodes, 1)[0]
        return app_node_index

    # generate remote node inside the network but outside the border and the veto region
    def generate_remote_node(self,startpoint):
        remote_node_index = random.sample(self.nodes, 1)[0]
        border_indexes = self.border_region.keys()
        veto_indexes = self.veto_region.keys()
        while remote_node_index in border_indexes or remote_node_index in veto_indexes or remote_node_index == startpoint:
            remote_node_index = random.sample(self.nodes, 1)[0]
        return remote_node_index

    def consumed_resources(self):
        residual_cpu = 0.0
        residual_bandwidth = 0.0
        for node in self.nodes:
            residual_cpu += self.nodes[node]['residual_cpu']
        for edge in self.edges:
            if self.edges[edge]['type'] is 'physical':
                residual_bandwidth += self.edges[edge]['residual_bandwidth']

        return ((self.cpu_capacity - residual_cpu) / self.cpu_capacity) * 100, ((self.bandwidth_capacity - residual_bandwidth) / self.bandwidth_capacity) * 100

    def consumed_region_cpu_resources(self,r_index):
        residual_cpu = 0.0
        total_cpu = 0.0
        for n_index, node in self.nodes.iteritems():
            if node['region'] == r_index:
                total_cpu += node['cpu']
                residual_cpu += node['residual_cpu']

        if total_cpu > 0:
            return ((total_cpu - residual_cpu) / total_cpu) * 100
        else:
            return 0

    # function that converts node indexes into labels
    def get_labelled_path(self,path):
        labelled_path = []
        list_path = list(path)
        for index in list_path:
            labelled_path.append(self.nodes[index]['label'])
        return labelled_path

    def node_label(self,index):
        return self.nodes[index]['label']

    # delete chains based on a given probability
    def delete_random_chains(self,end_prob):
        chain_indexes = []
        for key,chains in self.service_map.items():
            x = random.random()
            if x < end_prob:
                chain_indexes += chains
                del self.service_map[key]

        if len(chain_indexes) == 0:
            return

        chains_to_remove_from_chain_map = []
        chains_to_remove_from_region_cpu_map = []
        for index in chain_indexes:
            chains_to_remove_from_chain_map.append((index,self.chain_map[index]))
            chains_to_remove_from_region_cpu_map.append(index)
        for chain in chains_to_remove_from_chain_map:
            # releasing bandwidth and cpu resources
            for edge in chain[1]['resources']['links']:
                self.edges[(edge[0][0],edge[0][1])]['residual_bandwidth'] += edge[1]
                self.edges[(edge[0][1],edge[0][0])]['residual_bandwidth'] += edge[1]
            for node in chain[1]['resources']['nodes']:
                self.nodes[node[0]]['residual_cpu'] += node[1]
            del self.chain_map[chain[0]]
        # here we remove the selected entries in the region_cpu_map
        for index, region_list in self.region_cpu_map.iteritems():
            chains_to_remove_list = copy.deepcopy(chains_to_remove_from_region_cpu_map)
            for chain in region_list[:]:
                if chain[0] in chains_to_remove_list:
                    region_list.remove(chain)
                    chains_to_remove_list.remove(chain[0])
                if len(chains_to_remove_list) == 0:
                    break

    # here we store the chains that have been embedded with the information of the mapping between vnfs and node and the network latency
    # we use this information to check is a new security service compromises the end-to-end latency of these chains
    def store_chain_mapping(self,security_service_index, security_service, solution, vnf_node_mapping, vlink_edge_mapping):
        self.service_map[security_service_index] = []

        for c_index, c in enumerate(security_service):
            self.chain_map[self.chain_index] = {}
            self.chain_map[self.chain_index]['bandwidth'] = c[0]['bandwidth']
            self.chain_map[self.chain_index]['packet_size'] = c[0]['packet_size']
            self.chain_map[self.chain_index]['max_latency'] = c[0]['latency']
            self.chain_map[self.chain_index]['current_latency'] = solution['path_latency'][c_index]
            self.chain_map[self.chain_index]['map'] = []
            self.chain_map[self.chain_index]['regions'] = {}
            self.chain_map[self.chain_index]['resources'] = {'links':[],'nodes':[]}

            total_cpu = 0
            active_nodes = set()
            for map in vnf_node_mapping[c_index]:
                if map[0] is not None and c[0][map[0]]['id'] != 'app' and c[0][map[0]]['id'] != 'remote':
                    active_nodes.add(map[1])
                    self.chain_map[self.chain_index]['map'].append({'gu':c[0][map[0]]['cpu'],'node': map[1]})
                    total_cpu += c[0][map[0]]['cpu']
                    if self.nodes[map[1]]['region'] in self.chain_map[self.chain_index]['regions']:
                        self.chain_map[self.chain_index]['regions'][self.nodes[map[1]]['region']]['cpu'] += c[0][map[0]]['cpu']
                        self.chain_map[self.chain_index]['regions'][self.nodes[map[1]]['region']]['count'] += 1
                    else:
                        self.chain_map[self.chain_index]['regions'][self.nodes[map[1]]['region']] = {'cpu': c[0][map[0]]['cpu'],'count':1}

            # percentage of the CPU used in each region
            for index, value in self.chain_map[self.chain_index]['regions'].iteritems():
                self.chain_map[self.chain_index]['regions'][index]['cpu'] = float(value['cpu'])/total_cpu

            # here we find minimum average residual CPU capacity that allows he fulfillment of the latency constraint
            self.chain_map[self.chain_index]['network_latency'] = 0
            if c[0]['start_node'] == None or c[0]['end_node'] == None:
                self.chain_map[self.chain_index]['network_latency'] += INTERNET_LATENCY

            for vlink in vlink_edge_mapping[c_index]:
                for edge in vlink:
                    self.chain_map[self.chain_index]['network_latency'] += self.edges[edge]['latency']

            queuing_latency = self.local_network_tiers * SWITCH_QUEUING_DELAY * 2 * len(active_nodes)  # entering+exiting 1 or 2 nodes
            self.chain_map[self.chain_index]['network_latency'] += queuing_latency

            self.chain_map[self.chain_index]['min_total_gir'] = (total_cpu * c[0]['packet_size'])/ float(c[0]['latency'] - self.chain_map[self.chain_index]['network_latency'])

            # here we store the average CPU requirements for each chain in each region
            # we keep the one with highest requirement in front position
            for index, value in self.chain_map[self.chain_index]['regions'].iteritems():
                if index not in self.region_cpu_map:
                    self.region_cpu_map[index]=[]
                average_required_cpu = self.chain_map[self.chain_index]['min_total_gir'] * value['cpu']/value['count']
                if len (self.region_cpu_map[index]) > 0 and average_required_cpu > self.region_cpu_map[index][0][1]:
                    self.region_cpu_map[index].insert(0,(self.chain_index,average_required_cpu))
                else:
                    self.region_cpu_map[index].append((self.chain_index,average_required_cpu))

            #here we save the used resources in order to deallocate them when deleting the chains
            for vlink in vlink_edge_mapping[c_index]:
                for edge in vlink:
                    if self.edges[edge]['type'] == 'physical':
                        self.chain_map[self.chain_index]['resources']['links'].append((edge,c[0]['bandwidth']))
            for map in vnf_node_mapping[c_index]:
                if map[0] is not None and c[0][map[0]]['id'] != 'app' and c[0][map[0]]['id'] != 'remote':
                    self.chain_map[self.chain_index]['resources']['nodes'].append((map[1],c[0][map[0]]['cpu']*c[0]['bandwidth']))

            self.service_map[security_service_index].append(self.chain_index)
            self.chain_index += 1

    # this method checks if an embedding compromises the end-to-end latency of old chains
    def check_old_chains(self, security_service,vnf_node_mapping):
        # I compute here the division once for all

        average_residual_cpu = self.average_residual_cpu_regions(security_service, vnf_node_mapping)
        temporary_residual_cpu = self.temporary_residual_cpu(security_service, vnf_node_mapping)

        for index, value in self.region_cpu_map.iteritems():
            if len(value) > 0:
                if average_residual_cpu[index] < value[0][1]:
                    # the first chain failed the first check, then we perform a precise check for it and for some of the other chains
                    if self.check_chains(index,average_residual_cpu[index],temporary_residual_cpu) == False:
                        return False
        return True

    def check_chains(self,region_index,average_residual_cpu,temporary_residual_cpu):
        denominator_temporary_residual_cpu = {}

        for index in temporary_residual_cpu:
            denominator_temporary_residual_cpu[index] = 1/(temporary_residual_cpu[index]+delta)

        for chain_record in self.region_cpu_map[region_index]:
            # we check all the chains with cpu requirements higher than the average
            chain = chain_record[0]
            average_cpu = chain_record[1]
            if average_residual_cpu < average_cpu:
                updated_latency = self.chain_map[chain]['network_latency']
                for vnf in self.chain_map[chain]['map']:
                    updated_latency += (vnf['gu'] * self.chain_map[chain]['packet_size']) * denominator_temporary_residual_cpu[vnf['node']]

                if updated_latency > self.chain_map[chain]['max_latency']:
                    return False

        return True

    # simulation of the vsnf placement
    def temporary_residual_cpu(self, security_service,vnf_node_mapping):
        residual_cpu = OrderedDict()
        for node in self.nodes:
            residual_cpu[node] = self.nodes[node]['residual_cpu']

        for c_index, c in enumerate(security_service):
            for map in vnf_node_mapping[c_index]:
                if map[0] is not None:
                    Gu = c[0][map[0]]['cpu']
                    Guc = Gu * c[0]['bandwidth']
                    residual_cpu[map[1]] -= Guc

        return residual_cpu

    def average_residual_cpu_regions(self, security_service, vnf_node_mapping):
        residual_cpu = OrderedDict()
        average_residual_cpu = {}
        average_residual_count = {}
        for node in self.nodes:
            residual_cpu[node] = self.nodes[node]['residual_cpu']
            if self.nodes[node]['region'] in average_residual_cpu:
                average_residual_cpu[self.nodes[node]['region']] += self.nodes[node]['residual_cpu']
                average_residual_count[self.nodes[node]['region']] += 1
            else:
                average_residual_cpu[self.nodes[node]['region']] = self.nodes[node]['residual_cpu']
                average_residual_count[self.nodes[node]['region']] = 1

        for c_index, c in enumerate(security_service):
            for map in vnf_node_mapping[c_index]:
                if map[0] is not None:
                    Gu = c[0][map[0]]['cpu']
                    Guc = Gu * c[0]['bandwidth']
                    average_residual_cpu[self.nodes[map[1]]['region']] -= Guc


        for index, value in average_residual_cpu.iteritems():
            average_residual_cpu[index] = value/average_residual_count[index]

        return average_residual_cpu
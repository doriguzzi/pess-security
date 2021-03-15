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

import time as time
from network import *
from operator import itemgetter

STATEFUL_VNFS_CHECK_TIMEOUT = 1

class heuristic_algorithm:
    def __init__(self,physical_network,security_service,security_service_index, log_file, old_chain_test=True):
        self.pn= physical_network
        self.nodes = physical_network.nodes
        self.edges = physical_network.edges
        self.cmap = physical_network.chain_map
        self.nmap = physical_network.neighbors_map
        self.security_service = security_service['service']
        self.user_node = security_service['user_node']
        self.remote_node = security_service['remote_node']
        self.node_count = physical_network.node_count
        self.edge_count = physical_network.edge_count
        self.max_node_cpu = physical_network.max_node_cpu
        self.local_network_tiers = physical_network.local_network_tiers
        self.border_region = list(physical_network.border_region.keys())
        self.veto_region = list(physical_network.veto_region.keys())
        self.network_cpu_capacity = physical_network.cpu_capacity
        self.network_bandwidth_capacity = physical_network.bandwidth_capacity
        self.average_residual_bandwidth = sum(edge['residual_bandwidth'] for edge in self.edges.itervalues() if edge['type'] == 'physical')/self.edge_count
        self.security_service_index = security_service_index
        self.old_chain_test = old_chain_test
        self.filename = log_file

    def embed_service(self,print_result=True, save_stats=True):
        start_time = time.time()
        total_required_bandwidth = sum(chain[0]['bandwidth'] for chain in self.security_service)
        total_required_cpu = sum(chain[0][vnf]['cpu']*chain[0]['bandwidth'] for chain in self.security_service for vnf in range(chain[0]['length']))
        if len(self.border_region) > 0:
            total_required_cpu_border = sum(chain[0][vnf]['cpu'] * chain[0]['bandwidth'] for chain in self.security_service for vnf in range(chain[0]['length']) if chain[0][vnf]['border'] is True)
        else:
            total_required_cpu_border = 0

        if self.remote_node is not None:
            destinations = [self.remote_node]
        else:
            destinations = self.border_region

        # first we find the best path between the user node and the remote region
        initial_path = self.get_best_path_basic(self.user_node,destinations,total_required_bandwidth,total_required_cpu,total_required_cpu_border)
        if initial_path is None:
            best_paths = []
        elif len(initial_path) == 0:
            best_paths = self.paths_with_leaf_nodes_empty_path(self.user_node,destinations, total_required_bandwidth, total_required_cpu,total_required_cpu_border)
        else:
            # third, we check if we missed any good node because it was a leaf node ignored by the shortest path algorithm
            best_paths = self.paths_with_leaf_nodes(initial_path, total_required_bandwidth, total_required_cpu,total_required_cpu_border)

        if len(best_paths) == 0:
            if print_result is True:
                print "-----------------------"
                print "Infeasible security service! No paths available."
            if save_stats is True:
                solution_string = -1
                consumed_cpu, consumed_bandwidth = self.pn.consumed_resources()
                consumed_region_cpu = self.pn.consumed_region_cpu_resources(1)
                embedding_time = time.time() - start_time
                save_result(str(self.filename) + "-infeasible", self.security_service_index, self.pn.node_count, self.pn.physical_edge_count,
                            len(self.security_service), sum((c[0]['length'] - 2) for c_index, c in enumerate(self.security_service)), 0, 0, 0,
                            '{:010.7f}'.format(consumed_cpu), '{:010.7f}'.format(consumed_bandwidth), '{:010.7f}'.format(consumed_region_cpu),0,
                            len(self.pn.service_map), '{:010.4f}'.format(embedding_time), solution_string)
            return -1, embedding_time


        ordered_candidate_embeddings = sorted(best_paths, key=itemgetter('total_cost'))
        solution = []
        if self.old_chain_test == False:
            solution = ordered_candidate_embeddings[0]
        else:
            # here we check if the embeddings compromise the old chains
            for path_index in range(len(ordered_candidate_embeddings)):
                vnf_node_mapping, vlink_edge_mapping = self.get_service_mapping(ordered_candidate_embeddings[path_index]['embeddings'])
                if self.pn.check_old_chains(self.security_service,vnf_node_mapping) == True:
                    solution = ordered_candidate_embeddings[path_index]
                    break
            if len(solution) == 0: # all the candidate embeddings compromise the latency requirements of old chains
                if print_result is True:
                    print "-----------------------"
                    print "The new solution solution compromises the latency bounds of old chains. Infeasible security service!"
                if save_stats is True:
                    solution_string = -2
                    consumed_cpu, consumed_bandwidth = self.pn.consumed_resources()
                    consumed_region_cpu = self.pn.consumed_region_cpu_resources(1)
                    embedding_time = time.time() - start_time
                    save_result(str(self.filename) + "-infeasible", self.security_service_index,
                                self.pn.node_count, self.pn.physical_edge_count,
                                len(self.security_service),
                                sum((c[0]['length'] - 2) for c_index, c in enumerate(self.security_service)), 0, 0, 0,
                                '{:010.7f}'.format(consumed_cpu), '{:010.7f}'.format(consumed_bandwidth), '{:010.7f}'.format(consumed_region_cpu),0,
                                len(self.pn.service_map), '{:010.4f}'.format(embedding_time), solution_string)
                return -2, embedding_time


        vnf_node_mapping, vlink_edge_mapping = self.get_service_mapping(solution['embeddings'])

        #average_chain_latency = self.get_average_latency(solution)
        self.update_residual_bandwidth(vlink_edge_mapping)
        self.update_residual_cpu(vnf_node_mapping)
        consumed_cpu, consumed_bandwidth = self.pn.consumed_resources()
        consumed_region_cpu = self.pn.consumed_region_cpu_resources(1)
        self.pn.store_chain_mapping(self.security_service_index, self.security_service, solution, vnf_node_mapping, vlink_edge_mapping) #here we store some information of the new chains for the future
        if print_result is True:
            self.print_solution(vnf_node_mapping, vlink_edge_mapping)
            print "-----------------------"
            print "Objective value: ", solution['total_cost']
            print "Consumed resources (cpu, bandwidth): ", consumed_cpu, consumed_bandwidth
            print "-----------------------"
        if save_stats is True:
            # here we save the whole solution
            solution_string = 0#self.solution_to_string(vnf_node_mapping, vlink_edge_mapping)
            embedding_time = time.time() - start_time
            save_result(str(self.filename), self.security_service_index, self.pn.node_count,  self.pn.physical_edge_count, len(self.security_service),
                        sum((c[0]['length'] - 2) for c_index, c in enumerate(self.security_service)), '{:010.6f}'.format(solution['total_cost']),
                        '{:010.6f}'.format(solution['cpu_cost']), '{:010.6f}'.format(solution['bandwidth_cost']), '{:010.7f}'.format(consumed_cpu),
                        '{:010.7f}'.format(consumed_bandwidth), '{:010.7f}'.format(consumed_region_cpu), '{:010.8f}'.format(sum(solution['path_latency'].values())/len(solution['path_latency'])),
                        len(self.pn.service_map), '{:010.4f}'.format(embedding_time), solution_string)

        return float(solution['total_cost']), embedding_time

    # The dijkstra algorithm used to find the path tree between the source (start) and the destinations.
    # Destinations comprise all the nodes of a region, when a region is defined. Just one node otherwise.
    def get_best_path_basic(self, start, destinations, required_bandwidth, required_cpu, required_cpu_border):
        nodes_to_visit = {start}
        visited_nodes = set()
        # Distance from start to start is 0
        distance_from_start = {start: 0}
        tentative_parents = {}

        for endpoint in destinations[:]:
            end_cost,border_node = self.cpu_border_cost([start,endpoint], required_cpu_border)
            if border_node == -1:
                destinations.remove(endpoint)

        while nodes_to_visit:
            if set(destinations).issubset(visited_nodes):
                break
            # The next node should be the one with the smallest weight
            current = min([(distance_from_start[node], node) for node in nodes_to_visit])[1]

            nodes_to_visit.discard(current)
            visited_nodes.add(current)
            edges = self.nmap[current]
            unvisited_neighbours = set(edges).difference(visited_nodes)

            for neighbour in unvisited_neighbours:
                next_hop_distance = 1 if self.pn.unlimited_bandwidth == True else self.bandwidth_cost(current,
                                                                                                      neighbour,
                                                                                                      required_bandwidth)
                neighbour_distance = distance_from_start[current] + next_hop_distance

                if neighbour_distance < distance_from_start.get(neighbour, float('inf')):
                    distance_from_start[neighbour] = neighbour_distance
                    tentative_parents[neighbour] = current
                    nodes_to_visit.add(neighbour)

        best_path = []
        min_total_cost = float('inf')
        for end in destinations:
            if end in distance_from_start:
                path = self.build_path(tentative_parents, end)
                embeddings, cpu_cost, bandwidth_cost, latency = self.compute_path_properties(path, required_bandwidth, required_cpu, required_cpu_border)
                if embeddings is not None and cpu_cost + bandwidth_cost < min_total_cost:
                    best_path = {'path': path, 'embeddings': embeddings, 'total_cost': cpu_cost + bandwidth_cost, 'cpu_cost': cpu_cost, 'bandwidth_cost': bandwidth_cost, 'path_latency': latency}
                    min_total_cost = cpu_cost + bandwidth_cost

        return best_path

    # Dijsktra algorithm implemented using ONLY the residual bandwidth of links as metric
    def get_best_path_light(self, start, destinations, required_bandwidth):
        nodes_to_visit = {start}
        visited_nodes = set()
        # Distance from start to start is 0
        distance_from_start = {start: 0}
        tentative_parents = {}

        while nodes_to_visit:
            if destinations.issubset(visited_nodes):
                break
            # The next node should be the one with the smallest weight
            current = min([(distance_from_start[node], node) for node in nodes_to_visit])[1]

            nodes_to_visit.discard(current)
            visited_nodes.add(current)
            edges = self.nmap[current]
            unvisited_neighbours = set(edges).difference(visited_nodes)

            for neighbour in unvisited_neighbours:
                next_hop_distance = 1 if self.pn.unlimited_bandwidth == True else self.bandwidth_cost(current,
                                                                                                      neighbour,
                                                                                                      required_bandwidth)
                neighbour_distance = distance_from_start[current] + next_hop_distance

                if neighbour_distance < distance_from_start.get(neighbour, float('inf')):
                    distance_from_start[neighbour] = neighbour_distance
                    tentative_parents[neighbour] = current
                    nodes_to_visit.add(neighbour)

        paths = {}
        for end in destinations:
            if end in distance_from_start:
                path = self.build_path(tentative_parents, end)
                if len(path) > 0:
                    paths[end] = path

        return paths

    def build_path(self, tentative_parents, end):
        # if end not in tentative_parents:
        #     return None
        cursor = end
        path = []
        while cursor is not None:
            path.append(cursor)
            cursor = tentative_parents.get(cursor)
        return list(reversed(path))

    # Given a set of paths, this method looks it there is a good node outside these paths that was ignored because
    # it is a leaf in the network graph (limitation of the Dijsktra)
    # It returns a list that contains the new paths if they are better than the old ones, otherwise it keeps the old ones
    def paths_with_leaf_nodes(self, current_path, required_bandwidth, required_cpu, required_cpu_border):
        current_best_residual_cpu = 0
        current_best_total_cost = float('inf')
        current_best_node = None
        new_paths = []

        if len(current_path) == 0:
            return []

        new_paths = list([current_path])  # we keep the current paths
        start = current_path['path'][0]
        destination = current_path['path'][-1]
        # first, we find the best nodes in the current paths
        path = current_path['path']
        current_best_total_cost = current_path['total_cost'] if current_path['total_cost'] < current_best_total_cost else current_best_total_cost

        for node in path:
            if self.nodes[node]['residual_cpu'] > current_best_residual_cpu and self.nodes[node]['veto'] == 0:
                current_best_residual_cpu = self.nodes[node]['residual_cpu']
                current_best_node = node

        # second, we look for better nodes excluding the ones in the veto region and already included in the current paths
        good_nodes = [current_best_node] if current_best_node is not None else []
        for n_index, node in self.nodes.iteritems():
            if n_index not in path and node['residual_cpu'] > current_best_residual_cpu and node['veto'] == 0:
                good_nodes.append(n_index)

        # candidate best nodes do not include the endpoints
        candidate_best_nodes = set(good_nodes).difference([start,destination])
        # third, if we found something, we add them to the paths list (if they are better than the existing ones)
        subpaths_start = self.get_best_path_light(start, candidate_best_nodes, required_bandwidth)
        subpaths_dest = self.get_best_path_light(destination, candidate_best_nodes, required_bandwidth)

        for best_node, subpath_from_start in subpaths_start.iteritems():
            if best_node in subpaths_dest:
                subpath_from_dest = list(reversed(subpaths_dest[best_node]))
                del subpath_from_dest[0] # this node is already included in subpath_from_start
                new_path = subpath_from_start+subpath_from_dest
                new_embedding, cpu_cost, bandwidth_cost, new_latency = self.compute_path_properties(new_path,
                                                                                                     required_bandwidth,
                                                                                                     required_cpu,
                                                                                                     required_cpu_border)
                if new_embedding is not None:
                    if bandwidth_cost + cpu_cost < current_best_total_cost:
                        new_paths.append({'path': new_path, 'embeddings': new_embedding, 'total_cost': cpu_cost + bandwidth_cost,
                                  'cpu_cost': cpu_cost, 'bandwidth_cost': bandwidth_cost, 'path_latency': new_latency})

        return new_paths

    def paths_with_leaf_nodes_empty_path(self, start, destinations, required_bandwidth, required_cpu, required_cpu_border):
        current_best_total_cost = float('inf')
        nodes_in_paths = []
        new_paths = []

        # we look for nodes with enough residual cpu
        good_nodes = []
        for n_index, node in self.nodes.iteritems():
            if n_index not in nodes_in_paths and node['residual_cpu'] > required_cpu and node['veto'] == 0:
                good_nodes.append(n_index)

        # candidate best nodes do not include the endpoints
        candidate_best_nodes = set(good_nodes).difference([start] + destinations)
        # third, if we found something, we add them to the paths list (if they are better than the existing ones)
        subpaths_start = self.get_best_path_light(start, candidate_best_nodes, required_bandwidth)
        subpaths_dest = {}
        for destination in destinations:
            subpaths_dest[destination] = self.get_best_path_light(destination, candidate_best_nodes, required_bandwidth)

        for best_node, subpath_from_start in subpaths_start.iteritems():
            for destination in destinations:
                if best_node in subpaths_dest[destination]:
                    subpath_from_dest = list(reversed(subpaths_dest[destination][best_node]))
                    del subpath_from_dest[0]  # this node is already included in subpath_from_start
                    new_path = subpath_from_start + subpath_from_dest
                    new_embedding, cpu_cost, bandwidth_cost, new_latency = self.compute_path_properties(new_path,
                                                                                                         required_bandwidth,
                                                                                                         required_cpu,
                                                                                                         required_cpu_border)
                    if new_embedding is not None:
                        if bandwidth_cost + cpu_cost < current_best_total_cost:
                            new_paths.append(
                                {'path': new_path, 'embeddings': new_embedding, 'total_cost': cpu_cost + bandwidth_cost,
                                 'cpu_cost': cpu_cost, 'bandwidth_cost': bandwidth_cost, 'path_latency': new_latency})

        return new_paths

    def bandwidth_path_cost(self, path, total_required_bandwidth):
        link_cost = 0
        for node in range(len(path) - 1):
            link_cost += self.bandwidth_cost(path[node], path[node + 1], total_required_bandwidth)
        return link_cost

    # verifies and computes the computational capacity on the border
    def cpu_border_cost(self, path, total_required_cpu_border):
        border_node = None
        residual_cpu = OrderedDict()
        for node in path:
            residual_cpu[node] = self.nodes[node]['residual_cpu']
            if node in self.border_region:
                border_node = node

        # do we need to consider the border node?
        check_border_node = True if self.remote_node is None and \
                                    len(self.border_region) > 0 and \
                                    total_required_cpu_border > 0 else False

        if check_border_node == True:
            if border_node is None:
                return 0,None
            else:
                if residual_cpu[border_node] < total_required_cpu_border:
                    return float('inf'), -1
                else:
                    return total_required_cpu_border/(residual_cpu[border_node]+delta), border_node
        else:
            return 0,None

    # computes the cpu cost on the path and returns the best and the border nodes
    # error code: None = "ignore the value", -1 = no enough resources available
    def cpu_path_cost(self, path, total_required_cpu, total_required_cpu_border):
        if path is None or len(path) == 0:
            return float('inf'),[None,None]

        best_node = None
        no_border_best_node = None
        border_node = None
        max_residual_cpu = 0
        max_residual_cpu_no_border = 0

        # we find the best and the border nodes
        residual_cpu = OrderedDict()
        for node in path:
            rc = self.nodes[node]['residual_cpu']
            residual_cpu[node] = rc
            if rc > max_residual_cpu and node not in self.veto_region:
                best_node = node
                max_residual_cpu = rc
            if rc > max_residual_cpu_no_border and node not in self.veto_region and node not in self.border_region:
                no_border_best_node = node
                max_residual_cpu_no_border = rc
            if node in self.border_region and node == path[-1]:
                border_node = node

        # do we need to consider the border node?
        check_border_node = True if self.remote_node is None and \
                            len(self.border_region) > 0 and \
                            total_required_cpu_border > 0 else False

        no_border_required_cpu = total_required_cpu - total_required_cpu_border
        if check_border_node == True:
            if border_node is None or residual_cpu[border_node] < total_required_cpu_border: # no border
                return 1 / delta, [-1, -1]
            else:
                best_node = no_border_best_node if max_residual_cpu_no_border > (residual_cpu[border_node]-total_required_cpu_border) else border_node
                residual_cpu_best_node = residual_cpu[best_node] if best_node == no_border_best_node else (residual_cpu[border_node]-total_required_cpu_border)
                if residual_cpu_best_node < no_border_required_cpu:
                    return 1 / delta, [-1, -1]
                else:
                    return (total_required_cpu_border / (residual_cpu[border_node] + delta) + no_border_required_cpu / (residual_cpu[best_node] + delta)), [best_node, border_node]
        else:
            if max_residual_cpu < total_required_cpu:
                return 1 / delta, [-1, -1]
            else:
                return (total_required_cpu/(max_residual_cpu+delta)),[best_node,None]

    # Given a path, this function computes the embedding cost and the end-to-end latency for each chain of the service
    def compute_path_properties(self,path,required_bandwidth,required_cpu,required_cpu_border):
        if len(path) == 0:
            return None, None, None, None

        path_latency = 0
        link_cost = 0
        embeddings = OrderedDict()
        for node in range(len(path)-1):
            link_cost += self.bandwidth_cost(path[node],path[node+1],required_bandwidth)
            path_latency += self.edges[(path[node],path[node+1])]['latency']

        if self.remote_node is None:  # we add the internet latency only if the chain goes outside the TSP network
            path_latency += INTERNET_LATENCY

        latency = {}
        cpu_cost, best_nodes = self.cpu_path_cost(path, required_cpu, required_cpu_border)
        if best_nodes[0] < 0:
            return None, cpu_cost, link_cost, None
        for c_index,c in enumerate(self.security_service):
            latency[c_index] = path_latency
            tmp_embedding = OrderedDict()
            if c[0][0]['id'] == 'app':
                tmp_embedding[path[0]]=[0]
            else:
                tmp_embedding[path[-1]]=[0]

            for vnf in range(1,c[0]['length']-1):
                if self.vnf_on_border(c[0][vnf]) is False:
                    latency[c_index] += vnf_processing_delay(self.pn, c, best_nodes[0], vnf)
                    if best_nodes[0] in tmp_embedding:
                        tmp_embedding[best_nodes[0]].append(vnf)
                    else:
                        tmp_embedding[best_nodes[0]] = [vnf]
                else:
                    latency[c_index] += vnf_processing_delay(self.pn, c, path[-1], vnf)
                    if path[-1] in tmp_embedding:
                        tmp_embedding[path[-1]].append(vnf)
                    else:
                        tmp_embedding[path[-1]] = [vnf]

            active_nodes=0
            for key,value in tmp_embedding.iteritems():
                if value != [0] and value != [c[0]['length'] - 1]: #excluding those nodes hosting only "app" and "remote"
                    active_nodes +=1

            queuing_latency = self.local_network_tiers*SWITCH_QUEUING_DELAY*2*active_nodes #entering+exiting 1 or 2 nodes
            latency[c_index] += queuing_latency

            if latency[c_index] > c[0]['latency']: # here we check the latency constraint
                return None, cpu_cost, link_cost, latency[c_index]

            if c[0][0]['id'] == 'app':
                if path[-1] in tmp_embedding:
                    tmp_embedding[path[-1]].append(c[0]['length']-1)
                else:
                    tmp_embedding[path[-1]] = [c[0]['length'] - 1]
            else:
                if path[0] in tmp_embedding:
                    tmp_embedding[path[0]].append(c[0]['length']-1)
                else:
                    tmp_embedding[path[0]] = [c[0]['length'] - 1]

            #here we insert the missing nodes
            embeddings[c_index] = OrderedDict()
            tmp_path = path if c[0][0]['id'] == 'app' else list(reversed(path))

            index = 0
            for node in enumerate(tmp_path):
                if index < len(tmp_embedding) and node[1] == tmp_embedding.keys()[index]:
                    embeddings[c_index][node] = tmp_embedding[node[1]]
                    index +=1
                else:
                    embeddings[c_index][node] = []

        return embeddings, cpu_cost, link_cost, latency


     # general requirements to decide whether a vnf goes to the border or not
    def vnf_on_border(self,vnf):
        if self.remote_node is not None:
            return False
        elif vnf['border'] is True and len(self.border_region) > 0:
            return True
        elif vnf['border'] is True and len(self.border_region) == 0:
            return False
        elif vnf['border'] is False or len(self.border_region) == 0:
            return False
        elif vnf['border'] is False or len(self.border_region) > 0:
            return False

    # computation of the residual bandwidth after embedding a security service
    def update_residual_bandwidth(self,vlink_edge_mapping):
        for c_index, c in enumerate(self.security_service):
            bandwidth = c[0]['bandwidth']
            for vlink in vlink_edge_mapping[c_index]:
                for edge in vlink:
                    if self.edges[edge]['type'] is 'physical':  # we decrease the residual bandwidth only for "real" links
                        self.edges[(edge[0],edge[1])]['residual_bandwidth'] -= bandwidth # the direction of the chain
                        self.edges[(edge[1],edge[0])]['residual_bandwidth'] -= bandwidth # and the opposite direction

    # computation of the residual computational resources after embedding a security service
    def update_residual_cpu(self,vnf_node_mapping):
        for c_index, c in enumerate(self.security_service):
            for map in vnf_node_mapping[c_index]:
                if map[0] is not None:
                    Gu = c[0][map[0]]['cpu']
                    Guc = Gu * c[0]['bandwidth']
                    self.nodes[map[1]]['residual_cpu'] -= Guc

    def restore_residual_cpu(self,vnf_node_mapping):
        for c_index, c in enumerate(self.security_service):
            for map in vnf_node_mapping[c_index]:
                if map[0] is not None:
                    Gu = c[0][map[0]]['cpu']
                    Guc = Gu * c[0]['bandwidth']
                    self.nodes[map[1]]['residual_cpu'] += Guc


    def bandwidth_cost(self,nodeA,nodeB, required_bandwidth):
        if nodeA == nodeB:
            return 0

        residual_b = self.edges[(nodeA,nodeB)]['residual_bandwidth']

        if residual_b-required_bandwidth >= 0:
            return required_bandwidth/((residual_b) + delta)
        else:
            return float('inf')

    def cpu_cost(self,c,node,vnf):
        residual_c = self.nodes[node]['residual_cpu']
        Gu = c[0][vnf]['cpu']
        Guc =  Gu*c[0]['bandwidth']

        if residual_c-Guc > 0:
            return Guc/((residual_c) + delta)
        else:
            return float('inf')

    def check_latency_constraint(self, path):
        for c_index,c in enumerate(self.security_service):
            if path['path_latency'][c_index] > c[0]['latency']:
                return False

        return True

    def get_service_mapping(self, solution):
        vnf_node_mapping = OrderedDict()
        vlink_edge_mapping = OrderedDict()
        for c_index, c in enumerate(self.security_service):
            vnf_node_mapping[c_index] = []
            for node in solution[c_index]:
                if len(solution[c_index][node]) == 0:
                    vnf_node_mapping[c_index].append((None,node[1]))
                else:
                    for u in solution[c_index][node]:
                        vnf_node_mapping[c_index].append((u,node[1]))

        for c_index, c in enumerate(self.security_service):
            vlink_edge_mapping[c_index] = []
            previous_index = 0
            for u in range(c[0]['length']-1):
                vlinks = []
                for index in range(previous_index, len(vnf_node_mapping[c_index])-1):
                    pair = vnf_node_mapping[c_index][index]
                    pair_next = vnf_node_mapping[c_index][index+1]
                    if pair[0] < u+1:
                        vlinks.append((pair[1],pair_next[1]))
                    else:
                        previous_index = index
                        break
                vlink_edge_mapping[c_index].append(vlinks)

        return vnf_node_mapping, vlink_edge_mapping

    # print vnfs
    def print_solution(self, vnf_node_mapping, vlink_edge_mapping):
        for c_index, c in enumerate(self.security_service):
            print "-----------------------"
            print "Chain #", c_index
            for u in vnf_node_mapping[c_index]:
                if u[0] is not None:
                    print c[0][u[0]]['id'], self.nodes[u[1]]['label']

        for c_index, c in enumerate(self.security_service):
            print "-----------------------"
            print "Chain #", c_index
            for u in range(len(c[1])):
                print self.security_service[c_index][0][c[1][u][0]]['id'], self.security_service[c_index][0][c[1][u][1]]['id'],[self.edges[edge]['label'] for edge in vlink_edge_mapping[c_index][u]]

                # print vnfs

    # string with the solution
    def solution_to_string(self, vnf_node_mapping, vlink_edge_mapping):
        solution_string = ""
        for c_index, c in enumerate(self.security_service):
            tmp_string = "chain" + str(c_index) + "(B:" + str(c[0]['bandwidth']) + "-L:" + str(c[0]['latency']) + ")="
            for u in vnf_node_mapping[c_index]:
                if u[0] is not None:
                    tmp_string += "[" + str(c[0][u[0]]['id']) + "-" + self.pn.node_label(u[1]) + "]"
                    #print "################################"
                    #print vnf_processing_delay(self.pn, c, get_node_index(self.nodes,u[1]), u[0])
            solution_string += tmp_string + " "

        for c_index, c in enumerate(self.security_service):
            tmp_string = "chain" + str(c_index) + "(B:" + str(c[0]['bandwidth']) + "-L:" + str(c[0]['latency']) + ")="
            for u in range(len(c[1])):
                tmp_string += "[" + self.security_service[c_index][0][c[1][u][0]]['id'] + "-" + self.security_service[c_index][0][c[1][u][1]]['id'] +":"
                for i in range(len(vlink_edge_mapping[c_index][u])):
                    tmp_string += "("+ self.pn.node_label(vlink_edge_mapping[c_index][u][i][0]) + "-" + self.pn.node_label(vlink_edge_mapping[c_index][u][i][1]) + ")"
                tmp_string += "]"
            solution_string += tmp_string + " "
        return solution_string

    # string with part of the solution related to the chain specified in the parameters
    def chain_to_string(self, c_index, c, vnf_node_mapping, vlink_edge_mapping):
        solution_string = ""
        tmp_string = "chain" + str(c_index) + "(B:" + str(c[0]['bandwidth']) + "-L:" + str(
            c[0]['latency']) + ")="
        for u in vnf_node_mapping[c_index]:
            if u[0] is not None:
                tmp_string += "[" + str(c[0][u[0]]['id']) + "-" + str(u[1]) + "]"
                # print "################################"
                # print vnf_processing_delay(self.pn, c, get_node_index(self.nodes,u[1]), u[0])
        solution_string += tmp_string + " "

        tmp_string = "chain" + str(c_index) + "(B:" + str(c[0]['bandwidth']) + "-L:" + str(
            c[0]['latency']) + ")="
        for u in range(len(c[1])):
            tmp_string += "[" + self.security_service[c_index][0][c[1][u][0]]['id'] + "-" + \
                          self.security_service[c_index][0][c[1][u][1]]['id'] + ":"
            for i in range(len(vlink_edge_mapping[c_index][u])):
                tmp_string += "(" + str(vlink_edge_mapping[c_index][u][i][0]) + "-" + str(
                    vlink_edge_mapping[c_index][u][i][1]) + ")"
            tmp_string += "]"
        solution_string += tmp_string + " "
        return solution_string
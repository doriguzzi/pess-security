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

from network import *
import random
from operator import itemgetter

random.seed(SEED)

class virtual_network:
    def __init__(self,physical_network, debug=False):
        self.debug = debug
        self.pn = physical_network
        self.border_index = SECURITY_VNFS - SECURITY_VNFS / 4
        self.vnfs = self.init_security_vnfs()# if self.test is False else self.generate_random_vnfs()

    # generate N different VNFs
    def generate_random_vnfs(self):
        vnfs = []
        for i in range(SECURITY_VNFS):
            vnfs.append(OrderedDict([('id', 'vnf' + str(i)), ('cpu', random.uniform(MIN_CPU,MAX_CPU)), ('stateful', random.choice([True,False])), ('border', True if i >= self.border_index else False)]))
        return vnfs

    # generate N different VNFs for testing purposes
    def generate_vnfs(self):
        vnfs = []
        for i in range(SECURITY_VNFS):
            vnfs.append(OrderedDict([('id', 'vnf' + str(i)), ('cpu', min(i+1,MAX_CPU)), ('stateful', True if i%2 is 1 else False), ('border', True if i>=self.border_index else False)]))
        return vnfs

    # generate custom VNFs for debugging purposes
    def generate_custom_vnfs(self):
        vnfs = []
        vnfs.append(OrderedDict([('id', 'vnf7'), ('cpu', 8), ('stateful', True),('border', False)]))
        vnfs.append(OrderedDict([('id', 'vnf9'), ('cpu', 10), ('stateful', True), ('border', True)]))
        return vnfs

    # generate custom VNFs from journal paper table
    def init_security_vnfs(self):
        vnfs = []
        vnfs.append(OrderedDict([('id', 'vnf00'), ('name', 'suricata'), ('cpu', 8.2), ('stateful', True), ('border', True if len(vnfs) >= self.border_index else False)]))
        vnfs.append(OrderedDict([('id', 'vnf01'), ('name', 'openvpn'), ('cpu', 31), ('stateful', False), ('border', True if len(vnfs) >= self.border_index else False)]))
        vnfs.append(OrderedDict([('id', 'vnf02'), ('name', 'strongswan'), ('cpu', 16), ('stateful', False), ('border', True if len(vnfs) >= self.border_index else False)]))
        vnfs.append(OrderedDict([('id', 'vnf03'), ('name', 'fortigate_ssl_vpn'), ('cpu', 13.6), ('stateful', False), ('border', True if len(vnfs) >= self.border_index else False)]))
        vnfs.append(OrderedDict([('id', 'vnf04'), ('name', 'fortigate_ipsec_vpn'), ('cpu', 14.5), ('stateful', False), ('border', True if len(vnfs) >= self.border_index else False)]))
        vnfs.append(OrderedDict([('id', 'vnf05'), ('name', 'vsrx_fw'), ('cpu', 2.3), ('stateful', True), ('border', True if len(vnfs) >= self.border_index else False)]))
        vnfs.append(OrderedDict([('id', 'vnf06'), ('name', 'vsrx_ips'), ('cpu', 2.4), ('stateful', True), ('border', True if len(vnfs) >= self.border_index else False)]))
        vnfs.append(OrderedDict([('id', 'vnf07'), ('name', 'vsrx_mon'), ('cpu', 1.5), ('stateful', False), ('border', True if len(vnfs) >= self.border_index else False)]))
        vnfs.append(OrderedDict([('id', 'vnf08'), ('name', 'cisco_ids'), ('cpu', 4.2), ('stateful', True), ('border', True if len(vnfs) >= self.border_index else False)]))
        vnfs.append(OrderedDict([('id', 'vnf09'), ('name', 'cisco_aes_vpn'), ('cpu', 6.9), ('stateful', False), ('border', True if len(vnfs) >= self.border_index else False)]))
        vnfs.append(OrderedDict([('id', 'vnf10'), ('name', 'fortigate_tp'), ('cpu', 11.3), ('stateful', True), ('border', True if len(vnfs) >= self.border_index else False)]))
        vnfs.append(OrderedDict([('id', 'vnf11'), ('name', 'snort'), ('cpu', 9.5), ('stateful', True), ('border', True if len(vnfs) >= self.border_index else False)]))
        vnfs.append(OrderedDict([('id', 'vnf12'), ('name', 'fortigate_ngfw'), ('cpu', 9), ('stateful', True), ('border', True if len(vnfs) >= self.border_index else False)]))
        return vnfs

    # random generation of a security service composed of 1 to 5 chains. The user_node is fixed across the chains, while the remote_node may vary in the border region (see constraint 13)
    # randomly we generate a chain, or the one in the opposite direction or both
    # parameters are used for testing purposes only
    def generate_security_service(self,start=None,end=None,max_chains = None, nr_chains = None, nr_vnf = None, border_prob = 0.8, bandwidth=None, latency = None, packet_size= None):
        new_service = []
        if nr_chains is not None:
            chains = nr_chains
        elif max_chains is not None:
            chains = random.randint(1,max_chains)
        else:
            chains = random.randint(1, MAX_CHAINS)

        # the startpoint (the user) is common for all the chains in the service
        startpoint = self.pn.generate_app_node() if start is None else start
        # when endpoint in None, either leave it None (Internet) or generate a random endpoint that belongs to the TSP network (e.g., TSP cloud service)
        # the endpoint is in common between the two directions of the communication
        if end is None: endpoint = self.pn.generate_remote_node(startpoint) if random.randint(1,10) > 10*border_prob else None
        else: endpoint = end

        for chain_index in range(chains):
            outgoing = random.randint(0,1) if self.debug is False else 1
            if outgoing > 0:
                U = OrderedDict()
                Upairs = []
                U['start_node'] = startpoint
                U['end_node'] = endpoint # the end node is determine by the algorithm using constraint (13)
                U['bandwidth'] = random.randrange(MIN_BANDWIDTH, MAX_BANDWIDTH, 1000) if bandwidth is None else bandwidth
                U['latency'] = random.uniform(MIN_LATENCY, MAX_LATENCY) if latency is None else latency
                U['packet_size'] = random.uniform(MIN_PACKET_SIZE, MAX_PACKET_SIZE) if packet_size is None else packet_size

                chain_vnfs = random.sample(self.vnfs,random.randint(1,MAX_VNFS_PER_CHAIN)) if nr_vnf is None else random.sample(self.vnfs,random.randint(1,nr_vnf))
                chain_vnfs = sorted(chain_vnfs, key=itemgetter('id'))
                chain_vnfs.insert(0,OrderedDict([('id', 'app'), ('cpu', 0), ('stateful', False), ('border', False)]))
                chain_vnfs.append(OrderedDict([('id', 'remote'), ('cpu', 0), ('stateful', False), ('border', False)]))
                U['length'] = len(chain_vnfs)
                for i in range(U['length']):
                    U[i] = chain_vnfs[i]
                    if i < U['length']-1:
                        Upairs.append((i,i+1))
                new_service.append((U,Upairs))

            if self.debug is False and outgoing is 1: # we check the outgoing value to avoid having empty services
                incoming = 0
            elif self.debug is False and outgoing is 0: # we check the outgoing value to avoid having empty services
                incoming = 1
            elif self.debug is True: # in case of debug, we do not want the opposite chain
                incoming = 0

            if incoming > 0:
                U = OrderedDict()
                Upairs = []
                U['start_node'] = endpoint # the start node is determine by the algorithm using constraint (13)
                U['end_node'] = startpoint
                U['bandwidth'] = random.randrange(MIN_BANDWIDTH, MAX_BANDWIDTH, 1000) if bandwidth is None else bandwidth
                U['latency'] = random.uniform(MIN_LATENCY, MAX_LATENCY) if latency is None else latency
                U['packet_size'] = random.uniform(MIN_PACKET_SIZE,MAX_PACKET_SIZE) if packet_size is None else packet_size

                chain_vnfs = random.sample(self.vnfs, random.randint(1, MAX_VNFS_PER_CHAIN)) if nr_vnf is None else random.sample(self.vnfs, random.randint(1, nr_vnf))
                chain_vnfs = sorted(chain_vnfs, key=itemgetter('id'),reverse=True)
                chain_vnfs.insert(0, OrderedDict([('id', 'remote'), ('cpu', 0), ('stateful', False), ('border', False)]))
                chain_vnfs.append(OrderedDict([('id', 'app'), ('cpu', 0), ('stateful', False), ('border', False)]))
                U['length'] = len(chain_vnfs)
                for i in range(U['length']):
                    U[i] = chain_vnfs[i]
                    if i < U['length'] - 1:
                        Upairs.append((i, i + 1))
                new_service.append((U, Upairs))

        return {'user_node' : startpoint, 'remote_node' : endpoint, 'service' : new_service}

    # for comparison purposes, here we create a security service with only two chains, one for each direction
    # the two chains are the union of the VSNFs of an application-aware security service
    # this is the baseline approach, where services are povisioned regardless the specific security and QoS
    # requirements of the applications
    def generate_security_service_merged(self,application_aware_security_service):
        new_service = []
        security_service = application_aware_security_service['service']
        startpoint = application_aware_security_service['user_node']
        endpoint = application_aware_security_service['remote_node']
        U1 = OrderedDict()
        U2 = OrderedDict()
        U1pairs = []
        U2pairs = []
        U1['bandwidth'] = 0
        U2['bandwidth'] = 0
        U1['packet_size'] = 0
        U2['packet_size'] = 0
        U1['latency'] = float('inf')
        U2['latency'] = float('inf')
        U1['start_node'] = startpoint
        U1['end_node'] = endpoint
        U2['start_node'] = endpoint
        U2['end_node'] = startpoint
        U1[0] = OrderedDict([('id', 'app'), ('cpu', 0), ('stateful', False), ('border', False)])
        U1['length'] = 1
        U2[0] = OrderedDict([('id', 'remote'), ('cpu', 0), ('stateful', False), ('border', False)])
        U2['length'] = 1
        U1_VSNF = []
        U2_VSNF = []
        for c_index, c in enumerate(security_service):
            if c[0][0]['id'] == 'app':
                U1['bandwidth'] += c[0]['bandwidth']
                if c[0]['latency'] < U1['latency']: U1['latency'] = c[0]['latency']
                if c[0]['packet_size'] > U1['packet_size']: U1['packet_size'] = c[0]['packet_size']
                for u in range(c[0]['length']):
                    if c[0][u]['id'] != 'app' and c[0][u]['id'] != 'remote':
                        if c[0][u] not in U1_VSNF:
                            U1_VSNF.append(c[0][u])
            elif c[0][0]['id'] == 'remote':
                U2['bandwidth'] += c[0]['bandwidth']
                if c[0]['latency'] < U2['latency']: U2['latency'] = c[0]['latency']
                if c[0]['packet_size'] > U2['packet_size']: U2['packet_size'] = c[0]['packet_size']
                for u in range(c[0]['length']):
                    if c[0][u]['id'] != 'app' and c[0][u]['id'] != 'remote':
                        if c[0][u] not in U2_VSNF:
                            U2_VSNF.append(c[0][u])

        U1_VSNF_sorted = sorted(U1_VSNF, key=itemgetter('id'))
        for vnf in U1_VSNF_sorted:
            U1[U1['length']] = vnf
            U1['length'] += 1

        U2_VSNF_sorted = sorted(U2_VSNF, key=itemgetter('id'), reverse=True)
        for vnf in U2_VSNF_sorted:
            U2[U2['length']] = vnf
            U2['length'] += 1

        U1[U1['length']] = OrderedDict([('id', 'remote'), ('cpu', 0), ('stateful', False), ('border', False)])
        U1['length'] += 1
        U2[U2['length']] = OrderedDict([('id', 'app'), ('cpu', 0), ('stateful', False), ('border', False)])
        U2['length'] += 1

        for i in range(U1['length']):
            if i < U1['length'] - 1:
                U1pairs.append((i, i + 1))
        if U1['length'] > 2: # non empty
            new_service.append((U1, U1pairs))

        for i in range(U2['length']):
            if i < U2['length'] - 1:
                U2pairs.append((i, i + 1))
        if U2['length'] > 2:  # non empty
            new_service.append((U2, U2pairs))


        return {'user_node' : startpoint, 'remote_node' : endpoint, 'service' : new_service}

    # generation of random unidirectional point to point security services (no border region). Only used for scalability tests.
    def generate_p2p_security_service(self,start=None,end=None,max_chains = None, nr_vnf = None, bandwidth=None, latency = None, packet_size= None):
        new_service = []
        chains = random.randint(1,MAX_CHAINS) if max_chains is None else random.randint(1,max_chains)

        # the startpoint (the user) is common for all the chains in the service
        startpoint = self.pn.generate_app_node() if start is None else start
        # when endpoint in None, either leave it None (Internet) or generate a random endpoint that belongs to the TSP network (e.g., TSP cloud service)
        # the endpoint is in common between the two directions of the communication
        endpoint = self.pn.generate_remote_node(startpoint) if end is None else end

        for chain_index in range(chains):
            U = OrderedDict()
            Upairs = []
            U['start_node'] = startpoint
            U['end_node'] = endpoint # the end node is determine by the algorithm using constraint (13)
            U['bandwidth'] = random.randrange(MIN_BANDWIDTH, MAX_BANDWIDTH, 1000) if bandwidth is None else bandwidth
            U['latency'] = random.uniform(MIN_LATENCY, MAX_LATENCY) if latency is None else latency
            U['packet_size'] = random.uniform(MIN_PACKET_SIZE, MAX_PACKET_SIZE) if packet_size is None else packet_size

            chain_vnfs = random.sample(self.vnfs, random.randint(1, MAX_VNFS_PER_CHAIN)) if nr_vnf is None else random.sample(self.vnfs, random.randint(1, nr_vnf))
            chain_vnfs.insert(0,OrderedDict([('id', 'app'), ('cpu', 0), ('stateful', False), ('border', False)]))
            chain_vnfs.append(OrderedDict([('id', 'remote'), ('cpu', 0), ('stateful', False), ('border', False)]))
            U['length'] = len(chain_vnfs)
            for i in range(U['length']):
                U[i] = chain_vnfs[i]
                if i < U['length']-1:
                    Upairs.append((i,i+1))
            new_service.append((U,Upairs))

        return {'user_node' : startpoint, 'remote_node' : endpoint, 'service' : new_service}
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

#Sample commands
# Baseline comparison on random topologies: python2 solver.py -p -s 20 -e 1
# Baseline comparison on the GARR network: python2 solver.py -p -t data/garr-topology -e 2
# Baseline comparison on the Stanford backbone: python2 solver.py -p -t data/stanford-topology -e 3
# Scalability test: python2 solver.py -e 4
# Scalability test with regions: python2 solver.py -t data/garr-topology -e 5

import sys
import random
import numpy as np
import argparse
from datetime import datetime
import scipy.stats as stats
from heuristic_algorithm import *
from network import *
from virtual_network import *
from util_functions import *
from operator import itemgetter

random.seed(SEED)

test_set = {
    'baseline_comparison_random':1,
    'baseline_comparison_garr':2,
    'baseline_comparison_stanford':3,
    'scalability':4,
    'scalability_region':5
}

def solve_it(test, input_data=None, network_size=None, scalability_iterations=10, print_output=True,graph=False):
    lines = []
    parts = []
    ns = None

    if input_data is not None:
        # parse the input
        lines = input_data.split('\n')
        parts = lines[0].split()
    elif network_size is not None:
        if network_size == "random":
            ns = random.randint(10, 25)
        else:
            ns = int(network_size)
    else:
        print ("ERROR: Neither topology file nor network size provided!")
        return

    # Embedding time computed on random networks of different degrees
    if test == test_set['scalability']:
        now = datetime.now()
        log_file = now.strftime("SCALABILITY-%Y-%m-%d-%H-%M-%S")
        results_rnd = OrderedDict()
        experiments = scalability_iterations

        # Random networks of different sizes (number of nodes) and different degrees
        for network_size in [10,100,250,500,750,1000]:
            results_rnd[network_size] = []
            for network_degree in [1, 3, 5]:
                security_service_index = 1
                average_time = 0
                for experiment in range(0, experiments):
                    pn_random = physical_network(size=int(network_size),region_perc=0, degree=network_degree, unlimited_bandwidth=False)
                    pn_random.set_average_cpu_resources(32 * 2.1 * GHz)
                    vn = virtual_network(pn_random)
                    security_service = vn.generate_p2p_security_service() # no regions defined in the network for this test, so we generate point2point chains

                    heuristic = heuristic_algorithm(pn_random, security_service, security_service_index,str(network_degree) + "-" + log_file+ "-#" + str(network_size))
                    cost,embed_time = heuristic.embed_service(print_result=print_output)
                    security_service_index += 1
                    average_time += embed_time
                results_rnd[network_size].append('{:07.3f}'.format(1000*average_time/experiments))
        print (np.array(results_rnd.items()))

    # Embedding time measured at different region sizes
    elif test == test_set['scalability_region']:
        now = datetime.now()
        log_file = now.strftime("SCALABILITY-REGION-%Y-%m-%d-%H-%M-%S")
        results_rnd = OrderedDict()
        experiments = scalability_iterations

        # Random networks of degree 5, different sizes (number of nodes) and different region sizes (as % on the number of nodes)
        for network_size in [10,100,250,500,750,1000]:
            results_rnd[network_size] = []
            for region_size in [10, 25, 50]:
                security_service_index = 1
                average_time = 0
                for experiment in range(0, experiments):
                    pn_random = physical_network(size=int(network_size),region_perc=region_size,degree=5, unlimited_bandwidth=False)

                    pn_random.set_average_cpu_resources(32 * 2.1 * GHz)
                    vn = virtual_network(pn_random)
                    security_service = vn.generate_security_service()

                    heuristic = heuristic_algorithm(pn_random, security_service, security_service_index,str(region_size) + "-" + log_file+ "-#" + str(network_size))
                    cost,embed_time = heuristic.embed_service(print_result=print_output)
                    security_service_index += 1
                    average_time += embed_time
                results_rnd[network_size].append('{:07.3f}'.format(1000*average_time/experiments))

        # GARR network
        security_service_index = 1
        average_time = 0
        for experiment in range(0, experiments):
            pn_garr = physical_network(lines, parts, unlimited_bandwidth=False)
            pn_garr.set_average_cpu_resources(32 * 2.1 * GHz)
            network_size = pn_garr.node_count
            vn = virtual_network(pn_garr)
            security_service = vn.generate_security_service()

            heuristic = heuristic_algorithm(pn_garr, security_service, security_service_index, str(5) + "-" + log_file + "-#" + str(network_size))
            cost,embed_time = heuristic.embed_service(print_result=print_output)
            security_service_index += 1
            average_time += embed_time
        results_rnd["GARR"] = ['{:07.3f}'.format(1000 * average_time / experiments)]
        print (np.array(results_rnd.items()))

    # comparison between baseline and PESS with random topologies
    elif test == test_set['baseline_comparison_random']:
        now = datetime.now()
        log_file1 = now.strftime("RANDOM-PESS-%Y-%m-%d-%H-%M-%S")
        log_file2 = now.strftime("RANDOM-BASELINE-%Y-%m-%d-%H-%M-%S")
        network_degree = 2
        pn_random = physical_network(size=int(network_size), degree=network_degree, unlimited_bandwidth=False)
        pn_random.set_average_cpu_resources(32 * 2.1 * GHz)
        pn_random.set_exact_bandwidth_resources(100*1000*Mbit)
        network_size = pn_random.node_count
        m = 0.001  # average death rate
        t = 1. / m  # average holding time
        for l in [1,2,4,6,8,10,12,14,16,18,20]:
            security_service_index = 1
            pn_heuristic1 = copy.deepcopy(pn_random)
            pn_heuristic2 = copy.deepcopy(pn_random)
            vn = virtual_network(pn_random)
            while security_service_index <= 100000:
                intertime = random_exponential(l)
                end_prob = stats.expon.cdf(x=intertime, scale=t)

                # application-aware service
                security_service = vn.generate_security_service(max_chains=5,nr_vnf=3,border_prob=0)
                # application-agnostic service (with the same properties of the application-aware one)
                security_service_merged = vn.generate_security_service_merged(security_service)

                heuristic1 = heuristic_algorithm(pn_heuristic1, security_service, security_service_index,
                                                 str(l * t) + "-" + log_file1 + "-#" + str(network_size))
                heuristic1.embed_service(print_result=print_output)
                heuristic2 = heuristic_algorithm(pn_heuristic2, security_service_merged, security_service_index,
                                                 str(l * t) + "-" + log_file2 + "-#" + str(network_size))
                heuristic2.embed_service(print_result=print_output)

                # release resources
                pn_heuristic1.delete_random_chains(end_prob)
                pn_heuristic2.delete_random_chains(end_prob)

                security_service_index += 1

    # comparison between baseline and PESS on the GARR topology
    elif test == test_set['baseline_comparison_garr']:
        now = datetime.now()
        log_file1 = now.strftime("GARR-PESS-%Y-%m-%d-%H-%M-%S")
        log_file2 = now.strftime("GARR-BASELINE-%Y-%m-%d-%H-%M-%S")
        pn_garr = physical_network(lines, parts, local_network_tiers=3, unlimited_bandwidth=False)
        if graph == True:
            draw_graph(pn_garr.nodes,pn_garr.edges)
        pn_garr.set_average_cpu_resources(32 * 2.1 * GHz)
        network_size = pn_garr.node_count
        m = 0.001  # average death rate
        t = 1. / m  # average holding time
        for l in [1, 2, 4, 6, 8, 10, 12, 14, 16, 18, 20]:
            security_service_index = 1
            pn_heuristic1 = copy.deepcopy(pn_garr)
            pn_heuristic2 = copy.deepcopy(pn_garr)
            vn = virtual_network(pn_garr)
            while security_service_index <= 100000:
                intertime = random_exponential(l)
                end_prob = stats.expon.cdf(x=intertime, scale=t)

                # application-aware service
                security_service = vn.generate_security_service()
                # application-agnostic service (with the same properties of the application-aware one)
                security_service_merged = vn.generate_security_service_merged(security_service)

                heuristic1 = heuristic_algorithm(pn_heuristic1, security_service, security_service_index,
                                                 str(l * t) + "-" + log_file1 + "-#" + str(network_size))
                heuristic1.embed_service(print_result=print_output)
                heuristic2 = heuristic_algorithm(pn_heuristic2, security_service_merged, security_service_index,
                                                 str(l * t) + "-" + log_file2 + "-#" + str(network_size))
                heuristic2.embed_service(print_result=print_output)

                # release resources
                pn_heuristic1.delete_random_chains(end_prob)
                pn_heuristic2.delete_random_chains(end_prob)

                security_service_index += 1

    # comparison between baseline and PESS on the Stanford backbone topology
    elif test == test_set['baseline_comparison_stanford']:
        now = datetime.now()
        log_file1 = now.strftime("STANFORD-PESS-%Y-%m-%d-%H-%M-%S")
        log_file2 = now.strftime("STANFORD-BASELINE-%Y-%m-%d-%H-%M-%S")
        pn_stanford = physical_network(lines, parts, local_network_tiers=1, unlimited_bandwidth=False)
        if graph == True:
            draw_graph(pn_stanford.nodes,pn_stanford.edges)
        pn_stanford.set_average_cpu_resources(32 * 2.1 * GHz)
        network_size = pn_stanford.node_count
        m = 0.001  # average death rate
        t = 1. / m  # average holding time
        for l in [1,2,4,6,8,10,12,14,16,18,20]:
            security_service_index = 1
            pn_heuristic1 = copy.deepcopy(pn_stanford)
            pn_heuristic2 = copy.deepcopy(pn_stanford)
            vn = virtual_network(pn_stanford)
            while security_service_index <= 100000:
                intertime = random_exponential(l)
                end_prob = stats.expon.cdf(x=intertime,scale=t)

                # application-aware service
                security_service = vn.generate_security_service()
                # application-agnostic service (with the same properties of the application-aware one)
                security_service_merged = vn.generate_security_service_merged(security_service)

                heuristic1 = heuristic_algorithm(pn_heuristic1, security_service, security_service_index,
                                                 str(l*t) + "-" + log_file1 + "-#" + str(network_size))
                heuristic1.embed_service(print_result=print_output)
                heuristic2 = heuristic_algorithm(pn_heuristic2, security_service_merged, security_service_index,
                                                 str(l*t) + "-" + log_file2 + "-#" + str(network_size))
                heuristic2.embed_service(print_result=print_output)


                # release resources
                pn_heuristic1.delete_random_chains(end_prob)
                pn_heuristic2.delete_random_chains(end_prob)

                security_service_index += 1

def main(argv):
    input_data = None
    network_size = None
    help_string = 'python2.7 solver.py -e <experiment_type> -t <topology_file> -s <random_topology_size> -l <log_level (notset, debug)>\n'

    help_string += 'Experiment types codes: \n'

    sorted_test_set = sorted(test_set.items(), key=itemgetter(1))
    for key, code in sorted_test_set:
        help_string += str(code) + ": " + str(key) + "\n"

    parser = argparse.ArgumentParser(
        description='Embedding solver',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)

    parser.add_argument('-s', '--size', default=10, type=int,
                        help='Size of the random networks')

    parser.add_argument('-e', '--experiment', default=1, type=int,
                        help='Experiment types: 1=baseline_comparison_random, 2=baseline_comparison_garr, 3=baseline_comparison_stanford, 4=scalability, 5=scalability_region')

    parser.add_argument('-i', '--iterations', default=10, type=int,
                        help='Number of iterations of the scalability tests (the results are reported as the average time')

    parser.add_argument('-t', '--topology', nargs='+', type=str,
                        help='Topology specification file. If not indicated, a random topology will be generated instead.')

    parser.add_argument('-p','--print_output', help='Print process output', action='store_true')
    parser.add_argument('-d', '--display_topology', help='Display topology', action='store_true')

    args = parser.parse_args()

    if args.topology is not None:
        file_location = args.topology[0]
        with open(file_location, 'r') as input_data_file:
            input_data = input_data_file.read()
    elif args.size is not None:
        network_size = args.size

    if args.experiment is None:
        print (help_string)
    else:
        solve_it(args.experiment,input_data,network_size,args.iterations, args.print_output,args.display_topology)

if __name__ == "__main__":
    main(sys.argv[1:])

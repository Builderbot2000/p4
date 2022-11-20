import json

import networkx as nx

from app import NetworkApp
from rule import MatchPattern
from te_objs import PassByPathObjective, MinLatencyObjective, MaxBandwidthObjective
from utils_json import DefaultEncoder

class TEApp(NetworkApp):
    def __init__(self, topo_file, json_file, of_controller=None, priority=2):
        super(TEApp, self).__init__(topo_file, json_file, of_controller, priority)
        self.pass_by_paths_obj = [] # a list of PassByPathObjective objects 
        self.min_latency_obj = [] # a list of MinLatencyObjective objects
        self.max_bandwidth_obj = [] # a list of MaxBandwidthObjective objects
        self.mode = 'None'
    
    def add_pass_by_path_obj(self, pass_by_obj):
        self.pass_by_paths_obj.append(pass_by_obj)

    def add_min_latency_obj(self, min_lat_obj):
        self.min_latency_obj.append(min_lat_obj)

    def add_max_bandwidth_obj(self, max_bw_obj):
        self.max_bandwidth_obj.append(max_bw_obj)

    # This function reads the TE objectives in the `self.json_file`
    # Then, parses the JSON objects to the three list:
    #       self.pass_by_paths_obj
    #       self.min_latency_obj
    #       self.max_bandwidth_obj
    def from_json(self):
        with open('%s'% self.json_file) as f:
            # TODO: complete
            rules = json.load(f)
            for obj in rules.get('pass_by_paths'):
                self.add_pass_by_path_obj(obj)
            for obj in rules.get('min_latency'):
                self.add_min_latency_obj(obj)
            for obj in rules.get('max_bandwidth'):
                self.add_max_bandwidth_obj(obj)
    
    # Translates the TE objectives to the `json_file`
    def to_json(self, json_file):
        json_dict = {
            'pass_by_paths': self.pass_by_paths_obj,
            'min_latency': self.min_latency_obj,
            'max_bandwidth': self.max_bandwidth_obj,
        }

        with open('%s'% json_file, 'w', encoding='utf-8') as f:
            json.dump(json_dict, f, ensure_ascii=False, indent=4, cls=DefaultEncoder)

    # This function translates the objectives in `self.pass_by_paths_obj` to a list of Rules in `self.rules`
    # It should: 
    #   call `self.calculate_rules_for_path` as needed
    #   handle traffic in reverse direction when `symmetric` is True 
    #   call `self.send_openflow_rules()` at the end
    def provision_pass_by_paths(self):
        self.rules = []
        # TODO: complete
        for obj in self.pass_by_paths_obj:
            match_pattern = obj['match_pattern']
            pattern = MatchPattern(src_mac=match_pattern['src_mac'],
                                   dst_mac=match_pattern['dst_mac'],
                                   mac_proto=match_pattern['mac_proto'],
                                   ip_proto=match_pattern['ip_proto'],
                                   src_ip=match_pattern['src_ip'],
                                   dst_ip=match_pattern['dst_ip'],
                                   src_port=match_pattern['src_port'],
                                   dst_port=match_pattern['dst_port'],
                                   in_port=match_pattern['in_port'])
            
            path = []
            for s in obj['switches']:
                path.append(str(s))
            rules = self.calculate_rules_for_path(path, pattern, include_in_port=True)
            for r in rules:
                self.add_rule(r)
                
            if obj['symmetric'] == True:
                pattern = MatchPattern(src_mac=match_pattern['dst_mac'],
                                       dst_mac=match_pattern['src_mac'],
                                       mac_proto=match_pattern['mac_proto'],
                                       ip_proto=match_pattern['ip_proto'],
                                       src_ip=match_pattern['dst_ip'],
                                       dst_ip=match_pattern['src_ip'],
                                       src_port=match_pattern['dst_port'],
                                       dst_port=match_pattern['src_port'])
                
                path = []
                for s in reversed(obj['switches']):
                    path.append(str(s))
                rules = self.calculate_rules_for_path(path, pattern, include_in_port=True)
                for r in rules:
                    self.add_rule(r)
              
        self.send_openflow_rules()
        self.mode = 'pass_by'
            
    # This function translates the objectives in `self.min_latency_obj` to a list of Rules in `self.rules`
    # It should: 
    #   call `self.calculate_rules_for_path` as needed
    #   consider using the function `networkx.shortest_path` in the networkx package
    #   handle traffic in reverse direction when `symmetric` is True 
    #   call `self.send_openflow_rules()` at the end
    def provision_min_latency_paths(self):
        self.rules = []
        # TODO: complete
        for obj in self.min_latency_obj:
            match_pattern = obj['match_pattern']
            pattern = MatchPattern(src_mac=match_pattern['src_mac'],
                                   dst_mac=match_pattern['dst_mac'],
                                   mac_proto=match_pattern['mac_proto'],
                                   ip_proto=match_pattern['ip_proto'],
                                   src_ip=match_pattern['src_ip'],
                                   dst_ip=match_pattern['dst_ip'],
                                   src_port=match_pattern['src_port'],
                                   dst_port=match_pattern['dst_port'],
                                   in_port=match_pattern['in_port'])
            
            path = nx.shortest_path(self.topo, source=str(obj['src_switch']), target=str(obj['dst_switch']), weight='delay')
            rules = self.calculate_rules_for_path(path, pattern, include_in_port=True)
            for r in rules:
                self.add_rule(r)
                
            if obj['symmetric'] == True:    
                pattern = MatchPattern(src_mac=match_pattern['dst_mac'],
                                       dst_mac=match_pattern['src_mac'],
                                       mac_proto=match_pattern['mac_proto'],
                                       ip_proto=match_pattern['ip_proto'],
                                       src_ip=match_pattern['dst_ip'],
                                       dst_ip=match_pattern['src_ip'],
                                       src_port=match_pattern['dst_port'],
                                       dst_port=match_pattern['src_port'])
                
                path = nx.shortest_path(self.topo, source=str(obj['dst_switch']), target=str(obj['src_switch']), weight='delay')
                rules = self.calculate_rules_for_path(path, pattern, include_in_port=True)
                for r in rules:
                    self.add_rule(r)
                
        self.send_openflow_rules() 
        self.mode = 'min_latency' 

    # BONUS: 
    # This function translates the objectives in `self.max_bandwidth_obj` to a list of Rules in `self.rules`
    # It should: 
    #   call `self.calculate_rules_for_path` as needed
    #   consider what algorithms to use (from networkx) to calculate the paths
    #   handle traffic in reverse direction when `symmetric` is True 
    #   call `self.send_openflow_rules()` at the end
    def provision_max_bandwidth_paths(self):
        self.rules = []
        # TODO: complete
        for obj in self.max_bandwidth_obj:
            match_pattern = obj['match_pattern']
            pattern = MatchPattern(src_mac=match_pattern['src_mac'],
                                   dst_mac=match_pattern['dst_mac'],
                                   mac_proto=match_pattern['mac_proto'],
                                   ip_proto=match_pattern['ip_proto'],
                                   src_ip=match_pattern['src_ip'],
                                   dst_ip=match_pattern['dst_ip'],
                                   src_port=match_pattern['src_port'],
                                   dst_port=match_pattern['dst_port'],
                                   in_port=match_pattern['in_port'])
            
            paths = nx.all_simple_paths(self.topo, source=str(obj['src_switch']), target=str(obj['dst_switch']))
            candidates = []
            for p in paths:
                # print(p)
                min_bw = 1000000000
                for n in range(len(p)-1):
                    bw = self.topo[p[n]][p[n+1]]['bw']
                    if bw < min_bw:
                        min_bw = bw
                # print("min_bw: " + str(min_bw))
                candidates.append([p, min_bw])
                # print(candidates)
            path = max(candidates, key=lambda k: k[1])
            # print(path)
                    
            rules = self.calculate_rules_for_path(path[0], pattern, include_in_port=True)
            for r in rules:
                self.add_rule(r)
                
            if obj['symmetric'] == True:
                pattern = MatchPattern(src_mac=match_pattern['dst_mac'],
                                       dst_mac=match_pattern['src_mac'],
                                       mac_proto=match_pattern['mac_proto'],
                                       ip_proto=match_pattern['ip_proto'],
                                       src_ip=match_pattern['dst_ip'],
                                       dst_ip=match_pattern['src_ip'],
                                       src_port=match_pattern['dst_port'],
                                       dst_port=match_pattern['src_port'])
                
                paths = nx.all_simple_paths(self.topo, source=str(obj['dst_switch']), target=str(obj['src_switch']))
                candidates = []
                for p in paths:
                    # print(p)
                    min_bw = 1000000000
                    for n in range(len(p)-1):
                        bw = self.topo[p[n]][p[n+1]]['bw']
                        if bw < min_bw:
                            min_bw = bw
                    # print("min_bw: " + str(min_bw))
                    candidates.append([p, min_bw])
                    # print(candidates)
                path = max(candidates, key=lambda k: k[1])
                # print(path)
                
                rules = self.calculate_rules_for_path(path[0], pattern, include_in_port=True)
                for r in rules:
                    self.add_rule(r)
                
        self.send_openflow_rules() 
        self.mode = 'max_bandwidth'
    
    # BONUS: Used to react to changes in the network (the controller notifies the App)
    def on_notified(self, **kwargs):
        print("Recalculating TE rules...")
        if self.topo_file:
            self.topo = nx.read_graphml(self.topo_file)
        self.send_openflow_rules(delete=True)
        self.rules = []
        mode = kwargs['mode']
        if mode == 'pass_by':
            self.provision_pass_by_paths()
        elif mode == 'min_latency':
            self.provision_min_latency_paths()
        elif mode == 'max_bandwidth':
            self.provision_max_bandwidth_paths()

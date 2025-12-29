"""
Cluster Manager for SecureGuard Enhanced
Handles node clustering, load balancing, and distributed processing
"""

import threading
import time
import json
import socket
import requests
from collections import defaultdict
import logging

logger = logging.getLogger('secureguard')

class ClusterManager:
    """Manages cluster of SecureGuard nodes"""

    def __init__(self):
        self.nodes = {}  # node_id -> {'address': addr, 'status': 'active|inactive', 'last_heartbeat': timestamp}
        self.heartbeat_interval = 30
        self.node_timeout = 120
        self.heartbeat_thread = None
        self.running = False

    def add_node(self, node_id, address):
        """Add a node to the cluster"""
        self.nodes[node_id] = {
            'address': address,
            'status': 'active',
            'last_heartbeat': time.time(),
            'load': 0
        }
        logger.info(f"Added node {node_id} at {address}")

    def remove_node(self, node_id):
        """Remove a node from the cluster"""
        if node_id in self.nodes:
            del self.nodes[node_id]
            logger.info(f"Removed node {node_id}")

    def get_active_nodes(self):
        """Get list of active nodes"""
        return [node_id for node_id, data in self.nodes.items() if data['status'] == 'active']

    def update_node_load(self, node_id, load):
        """Update load for a node"""
        if node_id in self.nodes:
            self.nodes[node_id]['load'] = load

    def update_heartbeat(self, node_id):
        """Update heartbeat timestamp for a node"""
        if node_id in self.nodes:
            self.nodes[node_id]['last_heartbeat'] = time.time()
            self.nodes[node_id]['status'] = 'active'
            logger.info(f"Updated heartbeat for node {node_id}")

    def get_least_loaded_node(self):
        """Get the least loaded active node"""
        active_nodes = [(node_id, data) for node_id, data in self.nodes.items() if data['status'] == 'active']
        if not active_nodes:
            return None

        # Return node with lowest load
        return min(active_nodes, key=lambda x: x[1]['load'])[0]

    def send_heartbeat(self):
        """Send heartbeat to all nodes"""
        for node_id, node_data in self.nodes.items():
            try:
                response = requests.post(f"http://{node_data['address']}/cluster/heartbeat",
                                      timeout=5, json={'node_id': node_id})
                if response.status_code == 200:
                    node_data['last_heartbeat'] = time.time()
                    node_data['status'] = 'active'
                    # Update load from response
                    if 'load' in response.json():
                        node_data['load'] = response.json()['load']
                else:
                    node_data['status'] = 'inactive'
            except Exception as e:
                logger.warning(f"Heartbeat failed for node {node_id}: {e}")
                node_data['status'] = 'inactive'

    def check_node_timeouts(self):
        """Check for timed out nodes"""
        current_time = time.time()
        for node_id, node_data in list(self.nodes.items()):
            if current_time - node_data['last_heartbeat'] > self.node_timeout:
                logger.warning(f"Node {node_id} timed out")
                node_data['status'] = 'inactive'

    def heartbeat_worker(self):
        """Background heartbeat worker"""
        while self.running:
            try:
                self.send_heartbeat()
                self.check_node_timeouts()
            except Exception as e:
                logger.error(f"Heartbeat worker error: {e}")
            time.sleep(self.heartbeat_interval)

    def start_heartbeat(self):
        """Start heartbeat monitoring"""
        if not self.running:
            self.running = True
            self.heartbeat_thread = threading.Thread(target=self.heartbeat_worker, daemon=True)
            self.heartbeat_thread.start()
            logger.info("Cluster heartbeat monitoring started")

    def stop_heartbeat(self):
        """Stop heartbeat monitoring"""
        self.running = False
        if self.heartbeat_thread:
            self.heartbeat_thread.join()
        logger.info("Cluster heartbeat monitoring stopped")

    def distribute_request(self, request_data):
        """Distribute request to appropriate node"""
        target_node = self.get_least_loaded_node()
        if not target_node:
            return None

        try:
            node_address = self.nodes[target_node]['address']
            response = requests.post(f"http://{node_address}/api/process",
                                   json=request_data, timeout=10)
            return response.json()
        except Exception as e:
            logger.error(f"Request distribution failed: {e}")
            return None

class LoadBalancer:
    """Load balancer for distributing traffic across nodes"""

    def __init__(self, algorithm='round_robin'):
        self.backends = []  # List of backend addresses
        self.algorithm = algorithm
        self.current_index = 0
        self.health_status = {}  # address -> {'healthy': bool, 'last_check': timestamp}
        self.health_check_interval = 10
        self.health_thread = None
        self.running = False

    def add_backend(self, address):
        """Add a backend server"""
        if address not in self.backends:
            self.backends.append(address)
            self.health_status[address] = {'healthy': True, 'last_check': time.time()}
            logger.info(f"Added backend {address}")

    def remove_backend(self, address):
        """Remove a backend server"""
        if address in self.backends:
            self.backends.remove(address)
            if address in self.health_status:
                del self.health_status[address]
            logger.info(f"Removed backend {address}")

    def get_next_backend(self):
        """Get next backend using load balancing algorithm"""
        if not self.backends:
            return None

        healthy_backends = [addr for addr in self.backends
                          if self.health_status.get(addr, {}).get('healthy', False)]

        if not healthy_backends:
            return None

        if self.algorithm == 'round_robin':
            backend = healthy_backends[self.current_index % len(healthy_backends)]
            self.current_index += 1
            return backend
        elif self.algorithm == 'least_connections':
            # For now, just use round robin (would need connection tracking)
            backend = healthy_backends[self.current_index % len(healthy_backends)]
            self.current_index += 1
            return backend
        else:
            return healthy_backends[0]

    def check_backend_health(self, address):
        """Check health of a backend"""
        try:
            response = requests.get(f"http://{address}/api/health", timeout=5)
            return response.status_code == 200
        except:
            return False

    def health_check_worker(self):
        """Background health check worker"""
        while self.running:
            try:
                for address in self.backends:
                    healthy = self.check_backend_health(address)
                    self.health_status[address] = {
                        'healthy': healthy,
                        'last_check': time.time()
                    }
                    if not healthy:
                        logger.warning(f"Backend {address} is unhealthy")
            except Exception as e:
                logger.error(f"Health check error: {e}")
            time.sleep(self.health_check_interval)

    def start_health_checks(self):
        """Start health check monitoring"""
        if not self.running:
            self.running = True
            self.health_thread = threading.Thread(target=self.health_check_worker, daemon=True)
            self.health_thread.start()
            logger.info("Load balancer health checks started")

    def stop_health_checks(self):
        """Stop health check monitoring"""
        self.running = False
        if self.health_thread:
            self.health_thread.join()
        logger.info("Load balancer health checks stopped")

    def forward_request(self, request_data):
        """Forward request to backend"""
        backend = self.get_next_backend()
        if not backend:
            return None

        try:
            response = requests.post(f"http://{backend}/api/process",
                                   json=request_data, timeout=10)
            return response.json()
        except Exception as e:
            logger.error(f"Request forwarding failed: {e}")
            return None

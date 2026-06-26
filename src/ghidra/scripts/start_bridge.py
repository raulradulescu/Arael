# Start ghidra-bridge server when Ghidra starts
#@category Arael
#@author Arael  
#@description Starts ghidra-bridge server to enable remote Python access to Ghidra API

import os
import sys
from threading import Thread

print("=" * 80)
print("ARAEL BRIDGE STARTUP")
print("=" * 80)
sys.stdout.flush()

# Configuration
port = int(os.environ.get('GHIDRA_BRIDGE_PORT', '4768'))
host = os.environ.get('GHIDRA_BRIDGE_HOST', '0.0.0.0')

print("Port: {}".format(port))
print("Host: {}".format(host))
sys.stdout.flush()

# Fix import path issue
try:
    from ghidra_bridge.server import ghidra_bridge_port
    sys.modules['ghidra_bridge_port'] = ghidra_bridge_port
    print("Fixed ghidra_bridge_port import")
except:
    pass

# Import and start server
try:
    from ghidra_bridge.server import ghidra_bridge_server as gbs
    
    def run_bridge():
        server = gbs.GhidraBridgeServer(
            server_host=host,
            server_port=port,
            response_timeout=None
        )
        server.run()
    
    bridge_thread = Thread(target=run_bridge, daemon=True)
    bridge_thread.start()
    
    print("=" * 80)
    print("SUCCESS: Bridge running on {}:{}".format(host, port))
    print("=" * 80)
    sys.stdout.flush()
    
except Exception as e:
    print("ERROR: {}".format(str(e)))
    import traceback
    traceback.print_exc()
    sys.stdout.flush()



# tools
PX4 Force Flag 21196 Remote Exploitation PoC
  1. Force DISARM: disarm(reason, forced=true) 
  2. Force ARM:   arm(reason, from_external || !forced)
usage:
  python3 force_flag_poc.py --port 18570 [--target 1] [--scenario disarm|arm|both]

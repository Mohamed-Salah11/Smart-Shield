def normalize_interface_payload(data, interface_type):
    interface_type = interface_type.upper()

    defaults = {
        "LAN": {
            "description": "LAN",
            "ipv4_config_type": "static",
            "ipv6_config_type": "none",
            "block_private_networks": False,
            "block_bogon_networks": False,
        },
        "WAN": {
            "description": "WAN",
            "ipv4_config_type": "dhcp",
            "ipv6_config_type": "none",
            "block_private_networks": True,
            "block_bogon_networks": True,
        },
    }

    base = defaults[interface_type]

    return {
        "enable_interface": bool(data.get("enable_interface", True)),
        "description": data.get("description", base["description"]),
        "ipv4_config_type": data.get("ipv4_config_type", base["ipv4_config_type"]),
        "ipv6_config_type": data.get("ipv6_config_type", base["ipv6_config_type"]),
        "mac_address": data.get("mac_address", ""),
        "mtu": data.get("mtu", ""),
        "mss": data.get("mss", ""),
        "speed_and_duplex": data.get("speed_and_duplex", "default"),
        "ipv4_address": data.get("ipv4_address", ""),
        "ipv4_upstream_gateway": data.get("ipv4_upstream_gateway", ""),
        "username": data.get("username", ""),
        "password": data.get("password", ""),
        "dial_on_demand": bool(data.get("dial_on_demand", False)),
        "idle_timeout": int(data.get("idle_timeout", 0) or 0),
        "block_private_networks": bool(
            data.get("block_private_networks", base["block_private_networks"])
        ),
        "block_bogon_networks": bool(
            data.get("block_bogon_networks", base["block_bogon_networks"])
        ),
        "assigned_port": (data.get("assigned_port") or "").strip(),
    }
# Pillar Configuration

Nebula network topology and per-host settings are defined in Salt pillar data. This allows centralized management of your mesh network configuration while keeping sensitive data (like IP assignments and firewall rules) separate from states.

## Pillar Structure Overview

The pillar configuration has two main components:

1. **Common settings** - Network-wide configuration (lighthouses, DNS, default firewall rules)
2. **Host settings** - Per-minion configuration (IP address, groups, custom firewall rules)

## Common Configuration

Create `/srv/pillar/nebula/common.sls` for network-wide settings:

```yaml
nebula:
  # Global network settings
  lighthouse_port: 4242          # UDP port for lighthouse communication
  listen_port: 0                 # 0 = random port (recommended for non-lighthouses)
  network_cidr: "10.10.10.0/24"  # Your Nebula network CIDR
  dns_name: "nebula"             # DNS suffix for certificate names

  # Remote allow list - which external networks can reach this node
  remote_allow_list:
    '0.0.0.0/0': true            # Allow IPv4 from anywhere
    '::/0': false                # Disable IPv6 advertisement
    '169.254.0.0/16': false      # Block link-local addresses

  # Lighthouse definitions - your network's coordination points
  lighthouses:
    lighthouse01:
      nebula_ip: "10.10.10.1"
      public_ip: "203.0.113.10"  # Public IP or hostname
    lighthouse02:
      nebula_ip: "10.10.10.2"
      public_ip: "lighthouse02.example.com"

  # Default firewall rules (can be overridden per-host)
  firewall:
    outbound:
      - port: any
        proto: any
        host: any
        description: "Allow all outbound by default"

    inbound:
      - port: any
        proto: icmp
        host: any
        description: "Allow ICMP from any host"
```

## Host Configuration

Create a pillar file for each host that needs Nebula configuration. For example, `/srv/pillar/nebula/web01.sls`:

```yaml
nebula:
  hosts:
    web01:
      ip: "10.10.10.123/24"      # Nebula IP with CIDR notation
      groups:                     # Security groups for firewall rules
        - "web"
        - "production"
        - "monitoring-target"
      duration: "17532h"          # Certificate validity (2 years)

      # Local allow list - which local interfaces to use
      local_allow_list:
        '0.0.0.0/0': true

      # Host-specific firewall rules (replaces common defaults)
      firewall:
        inbound:
          - port: 22
            proto: tcp
            groups: ["admin"]
            description: "SSH from admin group"

          - port: 80
            proto: tcp
            groups: ["load-balancer"]
            description: "HTTP from load balancers"

          - port: 443
            proto: tcp
            groups: ["load-balancer"]
            description: "HTTPS from load balancers"

          - port: 10050
            proto: tcp
            groups: ["monitoring"]
            description: "Zabbix agent"

          - port: any
            proto: icmp
            host: any
            description: "ICMP from anywhere"

        outbound:
          - port: any
            proto: any
            host: any
            description: "Allow all outbound"
```

## Lighthouse Configuration

Lighthouses require special configuration. Create `/srv/pillar/nebula/lighthouse01.sls`:

```yaml
nebula:
  hosts:
    lighthouse01:
      ip: "10.10.10.1/24"
      is_lighthouse: true         # This node is a lighthouse
      groups:
        - "lighthouse"
        - "infrastructure"
      duration: "43800h"          # Longer validity for infrastructure

      # Lighthouses should listen on a fixed port
      # (configured via listen_port in common settings)

      firewall:
        inbound:
          - port: 4242
            proto: udp
            host: any
            description: "Nebula lighthouse port"

          - port: 22
            proto: tcp
            groups: ["admin"]
            description: "SSH access"

          - port: any
            proto: icmp
            host: any
            description: "ICMP"

        outbound:
          - port: any
            proto: any
            host: any
```

## Pillar Top File

Add the pillar definitions to `/srv/pillar/top.sls`:

```yaml
base:
  # Common settings for all minions
  '*':
    - nebula.common

  # Host-specific configurations
  'web01':
    - nebula.web01

  'web02':
    - nebula.web02

  'lighthouse01':
    - nebula.lighthouse01

  # Or use glob patterns
  'web*':
    - nebula.webservers

  'db*':
    - nebula.databases
```

## Advanced Configuration Options

### Unsafe Routes

Route traffic for external networks through Nebula nodes:

```yaml
nebula:
  hosts:
    gateway01:
      ip: "10.10.10.50/24"
      groups: ["gateway"]
      unsafe_routes:
        - route: "192.168.1.0/24"
          via: "10.10.10.50"
        - route: "172.16.0.0/12"
          via: "10.10.10.50"
```

### Subnets

Assign additional subnet routing to a host:

```yaml
nebula:
  hosts:
    router01:
      ip: "10.10.10.100/24"
      subnets:
        - "192.168.100.0/24"
        - "192.168.200.0/24"
```

### Advertise Addresses

For hosts behind NAT or with multiple interfaces:

```yaml
nebula:
  hosts:
    nat-host:
      ip: "10.10.10.75/24"
      advertise_addrs:
        - "203.0.113.50:4242"
```

### Calculated Remotes

For dynamic IP resolution:

```yaml
nebula:
  hosts:
    dynamic-host:
      ip: "10.10.10.80/24"
      calculated_remotes:
        '10.10.10.1':
          - mask: '0.0.0.0/0'
            port: 4242
```

## Refreshing Pillar Data

After modifying pillar files, refresh the pillar data:

```bash
# Refresh pillar for all minions
salt '*' saltutil.refresh_pillar

# Refresh for specific minions
salt 'web01' saltutil.refresh_pillar

# Verify pillar data
salt 'web01' pillar.get nebula
```

## Pillar Data Validation

Test pillar access from the master:

```bash
# Check what pillar data a minion receives
salt-run nebula.test_pillar_access minion_id=web01
```

This is useful for debugging certificate generation issues.

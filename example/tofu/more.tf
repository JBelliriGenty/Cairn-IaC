# A few inconsistencies on purpose: the Drift view and --check list them.

# Backup server: created by Tofu, but not in the Ansible inventory yet.
resource "proxmox_virtual_environment_container" "backup" {
  node_name = "pve2"
  vm_id     = 203

  initialization {
    hostname = "backup"
    ip_config {
      ipv4 {
        address = "10.0.0.23/24"
      }
    }
  }

  cpu {
    cores = 1
  }

  memory {
    dedicated = 1024
  }

  disk {
    datastore_id = "local-lvm"
    size         = 100
  }
}

# Its firewall is written but turned off: the rule protects nothing yet.
resource "proxmox_virtual_environment_firewall_options" "backup" {
  node_name    = "pve2"
  container_id = 203
  enabled      = false
  input_policy = "DROP"
}

resource "proxmox_virtual_environment_firewall_rules" "backup" {
  node_name    = "pve2"
  container_id = 203

  rule {
    type    = "in"
    action  = "ACCEPT"
    comment = "SSH from the LAN"
    proto   = "tcp"
    dport   = "22"
    source  = "10.0.0.0/24"
  }
}

# Rules for db without firewall options: Proxmox keeps the firewall off.
resource "proxmox_virtual_environment_firewall_rules" "db" {
  node_name = "pve2"
  vm_id     = 202

  rule {
    type    = "in"
    action  = "ACCEPT"
    comment = "PostgreSQL from web"
    proto   = "tcp"
    dport   = "5432"
    source  = "10.0.0.21/32"
  }
}

# Left behind: the guest 299 was removed, its firewall was not.
resource "proxmox_virtual_environment_firewall_rules" "old" {
  node_name    = "pve1"
  container_id = 299

  rule {
    type    = "in"
    action  = "ACCEPT"
    comment = "HTTP"
    proto   = "tcp"
    dport   = "80"
  }
}

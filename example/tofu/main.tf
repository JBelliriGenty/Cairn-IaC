# Web server: an LXC on pve1.
resource "proxmox_virtual_environment_container" "web" {
  node_name = "pve1"
  vm_id     = 201
  tags      = ["web"]

  initialization {
    hostname = "web"
    ip_config {
      ipv4 {
        address = "10.0.0.21/24"
        gateway = "10.0.0.1"
      }
    }
  }

  cpu {
    cores = 2
  }

  memory {
    dedicated = 2048
  }

  disk {
    datastore_id = "local-lvm"
    size         = 16
  }
}

# Database: a VM on pve2.
resource "proxmox_virtual_environment_vm" "db" {
  node_name = "pve2"
  vm_id     = 202
  name      = "db"

  cpu {
    cores = 4
  }

  memory {
    dedicated = 8192
  }

  disk {
    datastore_id = "local-lvm"
    interface    = "scsi0"
    size         = 64
  }

  initialization {
    ip_config {
      ipv4 {
        address = "10.0.0.22/24"
        gateway = "10.0.0.1"
      }
    }
  }
}

resource "proxmox_virtual_environment_firewall_rules" "web" {
  node_name    = "pve1"
  container_id = 201

  rule {
    type    = "in"
    action  = "ACCEPT"
    comment = "HTTPS from anywhere"
    proto   = "tcp"
    dport   = "443"
  }
  rule {
    type    = "out"
    action  = "ACCEPT"
    comment = "PostgreSQL to db"
    proto   = "tcp"
    dport   = "5432"
    dest    = "10.0.0.22/32"
  }
}

resource "proxmox_virtual_environment_firewall_options" "web" {
  node_name     = "pve1"
  container_id  = 201
  enabled       = true
  input_policy  = "DROP"
  output_policy = "DROP"
}

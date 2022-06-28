# DEVOPS-TP4

## Introduction

Terraform est un environnement logiciel d'« infrastructure as code » publié en open-source par la société HashiCorp. Cet outil permet d'automatiser la construction des ressources d'une infrastructure de centre de données comme un réseau, des machines virtuelles, un groupe de sécurité ou une base de données.

Le but de ce Tp est de créé à l’aide de terraform une machine virtuel avec un IP publique sur azure et de ce connecter sur cette VM.

## Création de la VM à l’aide de terraform

### data déja existante qu’on va utiliser

```tsx
data "azurerm_resource_group" "tp4" {
    name = "devops-TP2"  
}

data "azurerm_virtual_network" "tp4"{ # fait référence en écriture au virtual network
    name = "example-network"
    resource_group_name = "devops-TP2"
}

output "virtual_network_id" {
  value = data.azurerm_virtual_network.tp4.id
}

data "azurerm_subnet" "tp4"{ # fait référence en écriture au subnet
    name = "internal"
    resource_group_name = "devops-TP2"
    virtual_network_name = "example-network"
}
```

### Provider

```tsx
terraform {

  required_version = ">=0.12"

  required_providers {
    azurerm = {
      source = "hashicorp/azurerm"
      version = "~>2.0"
    }
  }
}
provider "azurerm"{
    features {}
    subscription_id = "765266c6-9a23-4638-af32-dd1e32613047"
}
```

### Variable pour définir la region utiliser sur Azure

```tsx
variable "region" {
    description = "Azure region" 
	default ="france Central"
	type =string
}
```

### Le code pour créer la vm et définir son adress publique

```tsx
resource "azurerm_public_ip" "myterraformpublicip" {
  name                = "PublicIP-20200828"
  location            = var.region
  resource_group_name = "devops-TP2"
  allocation_method   = "Dynamic"
}

# Create Network Security Group and rule
resource "azurerm_network_security_group" "myterraformnsg" {
  name                = "NetworkSecurityGroup-20200828"
  location            = var.region
  resource_group_name = "devops-TP2"

  security_rule {
    name                       = "SSH"
    priority                   = 1001
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "22"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }
}

# Create network interface
resource "azurerm_network_interface" "myterraformnic" {
  name                = "NIC-20200828"
  location            = var.region
  resource_group_name = data.azurerm_resource_group.tp4.name

  ip_configuration {
    name                          = "NicConfiguration-20200828"
    subnet_id                     = data.azurerm_subnet.tp4.id
    private_ip_address_allocation = "Dynamic"
    public_ip_address_id          = azurerm_public_ip.myterraformpublicip.id
  }
}

# Connect the security group to the network interface
resource "azurerm_network_interface_security_group_association" "example" {
  network_interface_id      = azurerm_network_interface.myterraformnic.id
  network_security_group_id = azurerm_network_security_group.myterraformnsg.id
}

# Generate random text for a unique storage account name
resource "random_id" "randomId" {
  keepers = {
    # Generate a new ID only when a new resource group is defined
    resource_group = data.azurerm_resource_group.tp4.name
  }

  byte_length = 8
}

# Create (and display) an SSH key
resource "tls_private_key" "example_ssh" {
  algorithm = "RSA"
  rsa_bits  = 4096
}

# Create virtual machine
resource "azurerm_linux_virtual_machine" "Devops-20200828" {
  name                  = "devops20200828"
  location              = data.azurerm_resource_group.tp4.location
  resource_group_name   = data.azurerm_resource_group.tp4.name
  network_interface_ids = [azurerm_network_interface.myterraformnic.id]
  size                  = "Standard_D2s_v3"

  os_disk {
    name                 = "OsDisk-20200828"
    caching              = "ReadWrite"
    storage_account_type = "Standard_LRS"
  }

  source_image_reference {
    publisher = "Canonical"
    offer     = "UbuntuServer"
    sku       = "18.04-LTS"
    version   = "latest"
  }

  computer_name                   = "devops20200828"
  admin_username                  = "azureuser"
  disable_password_authentication = true

  admin_ssh_key {
    username   = "azureuser"
    public_key = tls_private_key.example_ssh.public_key_openssh
  }

}
```

### Output pour récupérer l’adress publique et la clé privé pour ssh

```tsx
output "public_ip_address" {
  value = azurerm_linux_virtual_machine.Devops-20200828.public_ip_address
}

output "tls_private_key" {
  value     = tls_private_key.example_ssh.private_key_pem
  sensitive = true
}
```

## On lance le Script

### Init

```powershell
PS C:\Users\abdelhadi\Desktop\terraform> terraform init

Initializing the backend...

Initializing provider plugins...
- Reusing previous version of hashicorp/azurerm from the dependency lock file
- Reusing previous version of hashicorp/random from the dependency lock file
- Reusing previous version of hashicorp/tls from the dependency lock file
- Using previously-installed hashicorp/azurerm v2.99.0

Terraform has been successfully initialized!

You may now begin working with Terraform. Try running "terraform plan" to see
any changes that are required for your infrastructure. All Terraform commands
should now work.

If you ever set or change modules or backend configuration for Terraform,
rerun this command to reinitialize your working directory. If you forget, other
```

### Plan

```powershell
PS C:\Users\abdelhadi\Desktop\terraform> terraform plan -out main.tfplan   
data.azurerm_resource_group.tp4: Reading...
data.azurerm_virtual_network.tp4: Reading...
data.azurerm_subnet.tp4: Reading...
data.azurerm_resource_group.tp4: Read complete after 1s [id=/subscriptions/765266c6-9a23-4638-af32-dd1e32613047/resourceGroups/devops-TP2]
data.azurerm_virtual_network.tp4: Read complete after 1s [id=/subscriptions/765266c6-9a23-4638-af32-dd1e32613047/resourceGroups/devops-TP2/providers/Microsoft.Network/virtualNetworks/example-network]
data.azurerm_subnet.tp4: Read complete after 1s [id=/subscriptions/765266c6-9a23-4638-af32-dd1e32613047/resourceGroups/devops-TP2/providers/Microsoft.Network/virtualNetworks/example-network/subnets/internal]

Terraform used the selected providers to generate the following execution plan. Resource actions are indicated with the   
following symbols:
  + create

Terraform will perform the following actions:

  # azurerm_linux_virtual_machine.Devops-20200828 will be created
  + resource "azurerm_linux_virtual_machine" "Devops-20200828" {
      + admin_username                  = "azureuser"
      + allow_extension_operations      = true
      + computer_name                   = "devops20200828"
      + disable_password_authentication = true
      + extensions_time_budget          = "PT1H30M"
      + id                              = (known after apply)
      + location                        = "francecentral"
      + max_bid_price                   = -1
      + name                            = "devops20200828"
      + network_interface_ids           = (known after apply)
      + patch_mode                      = "ImageDefault"
      + platform_fault_domain           = -1
      + priority                        = "Regular"
      + private_ip_address              = (known after apply)
      + private_ip_addresses            = (known after apply)
      + provision_vm_agent              = true
      + public_ip_address               = (known after apply)
      + public_ip_addresses             = (known after apply)
      + resource_group_name             = "devops-TP2"
      + size                            = "Standard_D2s_v3"
      + virtual_machine_id              = (known after apply)
      + zone                            = (known after apply)

      + admin_ssh_key {
          + public_key = (known after apply)
          + username   = "azureuser"
        }

      + os_disk {
          + caching                   = "ReadWrite"
          + disk_size_gb              = (known after apply)
          + name                      = "OsDisk-20200828"
          + storage_account_type      = "Standard_LRS"
          + write_accelerator_enabled = false
        }

      + source_image_reference {
          + offer     = "UbuntuServer"
          + publisher = "Canonical"
          + sku       = "18.04-LTS"
          + version   = "latest"
        }
    }

  # azurerm_network_interface.myterraformnic will be created
  + resource "azurerm_network_interface" "myterraformnic" {
      + applied_dns_servers           = (known after apply)
      + dns_servers                   = (known after apply)
      + enable_accelerated_networking = false
      + enable_ip_forwarding          = false
      + id                            = (known after apply)
      + internal_dns_name_label       = (known after apply)
      + internal_domain_name_suffix   = (known after apply)
      + location                      = "francecentral"
      + mac_address                   = (known after apply)
      + name                          = "NIC-20200828"
      + private_ip_address            = (known after apply)
      + private_ip_addresses          = (known after apply)
      + resource_group_name           = "devops-TP2"
      + virtual_machine_id            = (known after apply)

      + ip_configuration {
          + gateway_load_balancer_frontend_ip_configuration_id = (known after apply)
          + name                                               = "NicConfiguration-20200828"
          + primary                                            = (known after apply)
          + private_ip_address                                 = (known after apply)
          + private_ip_address_allocation                      = "Dynamic"
          + private_ip_address_version                         = "IPv4"
          + public_ip_address_id                               = (known after apply)
          + subnet_id                                          = "/subscriptions/765266c6-9a23-4638-af32-dd1e32613047/resourceGroups/devops-TP2/providers/Microsoft.Network/virtualNetworks/example-network/subnets/internal"
        }
    }

  # azurerm_network_interface_security_group_association.example will be created
  + resource "azurerm_network_interface_security_group_association" "example" {
      + id                        = (known after apply)
      + network_interface_id      = (known after apply)
      + network_security_group_id = (known after apply)
    }

  # azurerm_network_security_group.myterraformnsg will be created
  + resource "azurerm_network_security_group" "myterraformnsg" {
      + id                  = (known after apply)
      + location            = "francecentral"
      + name                = "NetworkSecurityGroup-20200828"
      + resource_group_name = "devops-TP2"
      + security_rule       = [
          + {
              + access                                     = "Allow"
              + description                                = ""
              + destination_address_prefix                 = "*"
              + destination_address_prefixes               = []
              + destination_application_security_group_ids = []
              + destination_port_range                     = "22"
              + destination_port_ranges                    = []
              + direction                                  = "Inbound"
              + name                                       = "SSH"
              + priority                                   = 1001
              + protocol                                   = "Tcp"
              + source_address_prefix                      = "*"
              + source_address_prefixes                    = []
              + source_application_security_group_ids      = []
              + source_port_range                          = "*"
              + source_port_ranges                         = []
            },
        ]
    }

  # azurerm_public_ip.myterraformpublicip will be created
  + resource "azurerm_public_ip" "myterraformpublicip" {
      + allocation_method       = "Dynamic"
      + availability_zone       = (known after apply)
      + fqdn                    = (known after apply)
      + id                      = (known after apply)
      + idle_timeout_in_minutes = 4
      + ip_address              = (known after apply)
      + ip_version              = "IPv4"
      + location                = "francecentral"
      + name                    = "PublicIP-20200828"
      + resource_group_name     = "devops-TP2"
      + sku                     = "Basic"
      + sku_tier                = "Regional"
      + zones                   = (known after apply)
    }

  # random_id.randomId will be created
  + resource "random_id" "randomId" {
      + b64_std     = (known after apply)
      + b64_url     = (known after apply)
      + byte_length = 8
      + dec         = (known after apply)
      + hex         = (known after apply)
      + id          = (known after apply)
      + keepers     = {
          + "resource_group" = "devops-TP2"
        }
    }

  # tls_private_key.example_ssh will be created
  + resource "tls_private_key" "example_ssh" {
      + algorithm                     = "RSA"
      + ecdsa_curve                   = "P224"
      + id                            = (known after apply)
      + private_key_openssh           = (sensitive value)
      + private_key_pem               = (sensitive value)
      + public_key_fingerprint_md5    = (known after apply)
      + public_key_fingerprint_sha256 = (known after apply)
      + public_key_openssh            = (known after apply)
      + public_key_pem                = (known after apply)
      + rsa_bits                      = 4096
    }

Plan: 7 to add, 0 to change, 0 to destroy.

Changes to Outputs:
  + public_ip_address  = (known after apply)
  + tls_private_key    = (sensitive value)
  + virtual_network_id = "/subscriptions/765266c6-9a23-4638-af32-dd1e32613047/resourceGroups/devops-TP2/providers/Microsoft.Network/virtualNetworks/example-network"

───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── 

Saved the plan to: main.tfplan

To perform exactly these actions, run the following command to apply:
    terraform apply "main.tfplan"
```

### Login to azure

```powershell
PS C:\Users\abdelhadi\Desktop\terraform> az login
A web browser has been opened at https://login.microsoftonline.com/organizations/oauth2/v2.0/authorize. Please continue the login in the web browser. If no web browser is available or if the web browser fails to open, use device code flow with 
`az login --use-device-code`.
[
  {
    "cloudName": "AzureCloud",
    "homeTenantId": "413600cf-bd4e-4c7c-8a61-69e73cddf731",
    "id": "0824b62e-ae1f-4bec-b00b-66156e0a0dea",
    "isDefault": false,
    "managedByTenants": [],
    "name": "Azure for Students",
    "state": "Disabled",
    "tenantId": "413600cf-bd4e-4c7c-8a61-69e73cddf731",
    "user": {
      "name": "abdelhadi.hirchi@efrei.net",
      "type": "user"
    }
  },
```

### apply

```powershell
PS C:\Users\abdelhadi\Desktop\terraform> terraform apply
```

### La VM créé

![Untitled](DEVOPS-TP4%20fba78690481341af869df1982795f76a/Untitled.png)

### Extraction de la clé privé

```powershell
PS C:\Users\abdelhadi\Desktop\terraform> terraform output -raw tls_private_key > id_rsa3
```

![Untitled](DEVOPS-TP4%20fba78690481341af869df1982795f76a/Untitled%201.png)

### SSH connection to the VM

 

```powershell
abdel@LAPTOP-VKS08S91:/mnt/c/Users/abdelhadi/Desktop/terraform$ ssh -i ~/.ssh/id_rsa3 azureuser@20.216.132.94
Welcome to Ubuntu 18.04.6 LTS (GNU/Linux 5.4.0-1085-azure x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Mon Jun 27 16:07:55 UTC 2022

  System load:  0.0               Processes:           116
  Usage of /:   4.9% of 28.90GB   Users logged in:     0
  Memory usage: 2%                IP address for eth0: 10.3.1.6
  Swap usage:   0%

0 updates can be applied immediately.

The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.

To run a command as administrator (user "root"), use "sudo <command>".
See "man sudo_root" for details.
```

## Destroy the Build

```powershell
PS C:\Users\abdelhadi\Desktop\terraform> terraform destroy                              
tls_private_key.example_ssh: Refreshing state... [id=e9cc691ff5c8623884126a6a56ba2d971e944b57]
azurerm_public_ip.myterraformpublicip: Refreshing state... [id=/subscriptions/765266c6-9a23-4638-af32-dd1e32613047/resourceGroups/devops-TP2/providers/Microsoft.Network/publicIPAddresses/PublicIP-20200828]
data.azurerm_subnet.tp4: Reading...
data.azurerm_resource_group.tp4: Reading...
data.azurerm_virtual_network.tp4: Reading...
azurerm_network_security_group.myterraformnsg: Refreshing state... [id=/subscriptions/765266c6-9a23-4638-af32-dd1e32613047/resourceGroups/devops-TP2/providers/Microsoft.Network/networkSecurityGroups/NetworkSecurityGroup-20200828]
data.azurerm_resource_group.tp4: Read complete after 0s [id=/subscriptions/765266c6-9a23-4638-af32-dd1e32613047/resourceGroups/devops-TP2]
random_id.randomId: Refreshing state... [id=t5Iy4sqeJ4A]
data.azurerm_virtual_network.tp4: Read complete after 0s [id=/subscriptions/765266c6-9a23-4638-af32-dd1e32613047/resourceGroups/devops-TP2/providers/Microsoft.Network/virtualNetworks/example-network]
data.azurerm_subnet.tp4: Read complete after 9s [id=/subscriptions/765266c6-9a23-4638-af32-dd1e32613047/resourceGroups/devops-TP2/providers/Microsoft.Network/virtualNetworks/example-network/subnets/internal]
azurerm_network_interface.myterraformnic: Refreshing state... [id=/subscriptions/765266c6-9a23-4638-af32-dd1e32613047/resourceGroups/devops-TP2/providers/Microsoft.Network/networkInterfaces/NIC-20200828]
azurerm_network_interface_security_group_association.example: Refreshing state... [id=/subscriptions/765266c6-9a23-4638-af32-dd1e32613047/resourceGroups/devops-TP2/providers/Microsoft.Network/networkInterfaces/NIC-20200828|/subscriptions/765266c6-9a23-4638-af32-dd1e32613047/resourceGroups/devops-TP2/providers/Microsoft.Network/networkSecurityGroups/NetworkSecurityGroup-20200828]
azurerm_linux_virtual_machine.Devops-20200828: Refreshing state... [id=/subscriptions/765266c6-9a23-4638-af32-dd1e32613047/resourceGroups/devops-TP2/providers/Microsoft.Compute/virtualMachines/devops20200828]

Terraform used the selected providers to generate the following execution plan. Resource actions are indicated with the    
following symbols:
  - destroy

Terraform will perform the following actions:

  # azurerm_linux_virtual_machine.Devops-20200828 will be destroyed
  - resource "azurerm_linux_virtual_machine" "Devops-20200828" {
      - admin_username                  = "azureuser" -> null
      - allow_extension_operations      = true -> null
      - computer_name                   = "devops20200828" -> null
      - disable_password_authentication = true -> null
      - encryption_at_host_enabled      = false -> null
      - extensions_time_budget          = "PT1H30M" -> null
      - id                              = "/subscriptions/765266c6-9a23-4638-af32-dd1e32613047/resourceGroups/devops-TP2/providers/Microsoft.Compute/virtualMachines/devops20200828" -> null
      - location                        = "francecentral" -> null
      - max_bid_price                   = -1 -> null
      - name                            = "devops20200828" -> null
      - network_interface_ids           = [
          - "/subscriptions/765266c6-9a23-4638-af32-dd1e32613047/resourceGroups/devops-TP2/providers/Microsoft.Network/networkInterfaces/NIC-20200828",
        ] -> null
      - patch_mode                      = "ImageDefault" -> null
      - platform_fault_domain           = -1 -> null
      - priority                        = "Regular" -> null
      - private_ip_address              = "10.3.1.6" -> null
      - private_ip_addresses            = [
          - "10.3.1.6",
        ] -> null
      - provision_vm_agent              = true -> null
      - public_ip_address               = "20.216.132.94" -> null
      - public_ip_addresses             = [
          - "20.216.132.94",
        ] -> null
      - resource_group_name             = "devops-TP2" -> null
      - secure_boot_enabled             = false -> null
      - size                            = "Standard_D2s_v3" -> null
      - tags                            = {} -> null
      - virtual_machine_id              = "36fc0739-a411-4678-bf48-7d3370e57b1b" -> null
      - vtpm_enabled                    = false -> null

      - admin_ssh_key {
          - public_key = <<-EOT
                ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQCleFr7nJEqpsY7/Brtgt4TFtNW9wqj8QcXfxErD4ISv72vppToas+tX/cu+K/kb7tQhkZjd6GGuCC2M7oN4b8AArONeE511vVBVbfSMLrA0WzNGsPi6kJ67o0NOMOrDZq94iUZopzndsTlqyJNKOVcGuOvRpDbPcNRcu9jqlr5BXGv9GmiFD99+QgerkbEm0K3YzZ6PEjxWEEmKIeWvtqcflNqErSfD6KqqNZiF46JhcIfvBJwn3kCkL9xzHJC0X6A4W+Xyumf6wQK5t4ASMEOR1LSxuLrtVentacgZ0soyTfOFwdHW0HlGZV12p+NUqV+vkGdPU5L4Bi+ydZAUbelCLABi7WTgimy5v4fMJIuy9pJunDFnhR2Y/5/Zl0ax0a+LfKmh7gEQDa57l89EHrNSqt8YAjM8bLNM3nZlqgxImbtaJ47zphkpc4pXyvJle10u1ZAWb+7ns2IaO5T7/j3UO0Nq8/IyeiM3jcvrOSZ+kpY+TfwghuYkNOwa7w0e8U7QaivvlJYFH2wx5GVmwXskCnYB/7wVqvCu/d318qrl9dA4fMHd+1oxCHxX0z1G1RbcuPX1CLeVO7InV8tNkyX35ozZmHYFAmLJBL1Z+cdeCx9XPTI5M4B7ezEZ95Hv2LtgIeqLgyFdSLyvZL6sYLMYejzkc0DfpJwRKDxc2QwWQ==
            EOT -> null
          - username   = "azureuser" -> null
        }

      - os_disk {
          - caching                   = "ReadWrite" -> null
          - disk_size_gb              = 30 -> null
          - name                      = "OsDisk-20200828" -> null
          - storage_account_type      = "Standard_LRS" -> null
          - write_accelerator_enabled = false -> null
        }

      - source_image_reference {
          - offer     = "UbuntuServer" -> null
          - publisher = "Canonical" -> null
          - sku       = "18.04-LTS" -> null
          - version   = "latest" -> null
        }
    }

  # azurerm_network_interface.myterraformnic will be destroyed
  - resource "azurerm_network_interface" "myterraformnic" {
      - applied_dns_servers           = [] -> null
      - dns_servers                   = [] -> null
      - enable_accelerated_networking = false -> null
      - enable_ip_forwarding          = false -> null
      - id                            = "/subscriptions/765266c6-9a23-4638-af32-dd1e32613047/resourceGroups/devops-TP2/providers/Microsoft.Network/networkInterfaces/NIC-20200828" -> null
      - internal_domain_name_suffix   = "gewlwhk4qhwebidczoweta4psd.parx.internal.cloudapp.net" -> null
      - location                      = "francecentral" -> null
      - mac_address                   = "00-0D-3A-E7-7D-97" -> null
      - name                          = "NIC-20200828" -> null
      - private_ip_address            = "10.3.1.6" -> null
      - private_ip_addresses          = [
          - "10.3.1.6",
        ] -> null
      - resource_group_name           = "devops-TP2" -> null
      - tags                          = {} -> null
      - virtual_machine_id            = "/subscriptions/765266c6-9a23-4638-af32-dd1e32613047/resourceGroups/devops-TP2/providers/Microsoft.Compute/virtualMachines/devops20200828" -> null

      - ip_configuration {
          - name                          = "NicConfiguration-20200828" -> null
          - primary                       = true -> null
          - private_ip_address            = "10.3.1.6" -> null
          - private_ip_address_allocation = "Dynamic" -> null
          - private_ip_address_version    = "IPv4" -> null
          - public_ip_address_id          = "/subscriptions/765266c6-9a23-4638-af32-dd1e32613047/resourceGroups/devops-TP2/providers/Microsoft.Network/publicIPAddresses/PublicIP-20200828" -> null
          - subnet_id                     = "/subscriptions/765266c6-9a23-4638-af32-dd1e32613047/resourceGroups/devops-TP2/providers/Microsoft.Network/virtualNetworks/example-network/subnets/internal" -> null
        }
    }

  # azurerm_network_interface_security_group_association.example will be destroyed
  - resource "azurerm_network_interface_security_group_association" "example" {
      - id                        = "/subscriptions/765266c6-9a23-4638-af32-dd1e32613047/resourceGroups/devops-TP2/providers/Microsoft.Network/networkInterfaces/NIC-20200828|/subscriptions/765266c6-9a23-4638-af32-dd1e32613047/resourceGroups/devops-TP2/providers/Microsoft.Network/networkSecurityGroups/NetworkSecurityGroup-20200828" -> null
      - network_interface_id      = "/subscriptions/765266c6-9a23-4638-af32-dd1e32613047/resourceGroups/devops-TP2/providers/Microsoft.Network/networkInterfaces/NIC-20200828" -> null
      - network_security_group_id = "/subscriptions/765266c6-9a23-4638-af32-dd1e32613047/resourceGroups/devops-TP2/providers/Microsoft.Network/networkSecurityGroups/NetworkSecurityGroup-20200828" -> null
    }

  # azurerm_network_security_group.myterraformnsg will be destroyed
  - resource "azurerm_network_security_group" "myterraformnsg" {
      - id                  = "/subscriptions/765266c6-9a23-4638-af32-dd1e32613047/resourceGroups/devops-TP2/providers/Microsoft.Network/networkSecurityGroups/NetworkSecurityGroup-20200828" -> null
      - location            = "francecentral" -> null
      - name                = "NetworkSecurityGroup-20200828" -> null
      - resource_group_name = "devops-TP2" -> null
      - security_rule       = [
          - {
              - access                                     = "Allow"
              - description                                = ""
              - destination_address_prefix                 = "*"
              - destination_address_prefixes               = []
              - destination_application_security_group_ids = []
              - destination_port_range                     = "22"
              - destination_port_ranges                    = []
              - direction                                  = "Inbound"
              - name                                       = "SSH"
              - priority                                   = 1001
              - protocol                                   = "Tcp"
              - source_address_prefix                      = "*"
              - source_address_prefixes                    = []
              - source_application_security_group_ids      = []
              - source_port_range                          = "*"
              - source_port_ranges                         = []
            },
        ] -> null
      - tags                = {} -> null
    }

  # azurerm_public_ip.myterraformpublicip will be destroyed
  - resource "azurerm_public_ip" "myterraformpublicip" {
      - allocation_method       = "Dynamic" -> null
      - availability_zone       = "No-Zone" -> null
      - id                      = "/subscriptions/765266c6-9a23-4638-af32-dd1e32613047/resourceGroups/devops-TP2/providers/Microsoft.Network/publicIPAddresses/PublicIP-20200828" -> null
      - idle_timeout_in_minutes = 4 -> null
      - ip_address              = "20.216.132.94" -> null
      - ip_tags                 = {} -> null
      - ip_version              = "IPv4" -> null
      - location                = "francecentral" -> null
      - name                    = "PublicIP-20200828" -> null
      - resource_group_name     = "devops-TP2" -> null
      - sku                     = "Basic" -> null
      - sku_tier                = "Regional" -> null
      - tags                    = {} -> null
      - zones                   = [] -> null
    }

  # random_id.randomId will be destroyed
  - resource "random_id" "randomId" {
      - b64_std     = "t5Iy4sqeJ4A=" -> null
      - b64_url     = "t5Iy4sqeJ4A" -> null
      - byte_length = 8 -> null
      - dec         = "13227691005183928192" -> null
      - hex         = "b79232e2ca9e2780" -> null
      - id          = "t5Iy4sqeJ4A" -> null
      - keepers     = {
          - "resource_group" = "devops-TP2"
        } -> null
    }

  # tls_private_key.example_ssh will be destroyed
  - resource "tls_private_key" "example_ssh" {
      - algorithm                     = "RSA" -> null
      - ecdsa_curve                   = "P224" -> null
      - id                            = "e9cc691ff5c8623884126a6a56ba2d971e944b57" -> null
      - private_key_openssh           = (sensitive value)
      - private_key_pem               = (sensitive value)
      - public_key_fingerprint_md5    = "7b:36:07:1a:e2:06:bd:e9:3d:7e:eb:bc:58:59:38:34" -> null
      - public_key_fingerprint_sha256 = "SHA256:fhV+mWes/utN831H47xXW7A2ytj9CE2mIPR6HvEp8UM" -> null
      - public_key_openssh            = <<-EOT
            ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQCleFr7nJEqpsY7/Brtgt4TFtNW9wqj8QcXfxErD4ISv72vppToas+tX/cu+K/kb7tQhkZjd6GGuCC2M7oN4b8AArONeE511vVBVbfSMLrA0WzNGsPi6kJ67o0NOMOrDZq94iUZopzndsTlqyJNKOVcGuOvRpDbPcNRcu9jqlr5BXGv9GmiFD99+QgerkbEm0K3YzZ6PEjxWEEmKIeWvtqcflNqErSfD6KqqNZiF46JhcIfvBJwn3kCkL9xzHJC0X6A4W+Xyumf6wQK5t4ASMEOR1LSxuLrtVentacgZ0soyTfOFwdHW0HlGZV12p+NUqV+vkGdPU5L4Bi+ydZAUbelCLABi7WTgimy5v4fMJIuy9pJunDFnhR2Y/5/Zl0ax0a+LfKmh7gEQDa57l89EHrNSqt8YAjM8bLNM3nZlqgxImbtaJ47zphkpc4pXyvJle10u1ZAWb+7ns2IaO5T7/j3UO0Nq8/IyeiM3jcvrOSZ+kpY+TfwghuYkNOwa7w0e8U7QaivvlJYFH2wx5GVmwXskCnYB/7wVqvCu/d318qrl9dA4fMHd+1oxCHxX0z1G1RbcuPX1CLeVO7InV8tNkyX35ozZmHYFAmLJBL1Z+cdeCx9XPTI5M4B7ezEZ95Hv2LtgIeqLgyFdSLyvZL6sYLMYejzkc0DfpJwRKDxc2QwWQ==  
        EOT -> null
      - public_key_pem                = <<-EOT
            -----BEGIN PUBLIC KEY-----
            MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEApXha+5yRKqbGO/wa7YLe
            ExbTVvcKo/EHF38RKw+CEr+9r6aU6GrPrV/3Lviv5G+7UIZGY3ehhrggtjO6DeG/
            AAKzjXhOddb1QVW30jC6wNFszRrD4upCeu6NDTjDqw2aveIlGaKc53bE5asiTSjl
            XBrjr0aQ2z3DUXLvY6pa+QVxr/RpohQ/ffkIHq5GxJtCt2M2ejxI8VhBJiiHlr7a
            nH5TahK0nw+iqqjWYheOiYXCH7wScJ95ApC/ccxyQtF+gOFvl8rpn+sECubeAEjB
            DkdS0sbi67VXp7WnIGdLKMk3zhcHR1tB5RmVddqfjVKlfr5BnT1OS+AYvsnWQFG3
            pQiwAYu1k4Ipsub+HzCSLsvaSbpwxZ4UdmP+f2ZdGsdGvi3ypoe4BEA2ue5fPRB6
            zUqrfGAIzPGyzTN52ZaoMSJm7WieO86YZKXOKV8ryZXtdLtWQFm/u57NiGjuU+/4
            91DtDavPyMnojN43L6zkmfpKWPk38IIbmJDTsGu8NHvFO0Gor75SWBR9sMeRlZsF
            7JAp2Af+8Farwrv3d9fKq5fXQOHzB3ftaMQh8V9M9RtUW3Lj19Qi3lTuyJ1fLTZM
            l9+aM2Zh2BQJiyQS9WfnHXgsfVz0yOTOAe3sxGfeR79i7YCHqi4MhXUi8r2S+rGC
            zGHo85HNA36ScESg8XNkMFkCAwEAAQ==
            -----END PUBLIC KEY-----
        EOT -> null
      - rsa_bits                      = 4096 -> null
    }

Plan: 0 to add, 0 to change, 7 to destroy.

Changes to Outputs:
  - public_ip_address  = "20.216.132.94" -> null
  - tls_private_key    = (sensitive value)
  - virtual_network_id = "/subscriptions/765266c6-9a23-4638-af32-dd1e32613047/resourceGroups/devops-TP2/providers/Microsoft.Network/virtualNetworks/example-network" -> null

Do you really want to destroy all resources?
  Terraform will destroy all your managed infrastructure, as shown above.
  There is no undo. Only 'yes' will be accepted to confirm.

  Enter a value: yes

random_id.randomId: Destroying... [id=t5Iy4sqeJ4A]
random_id.randomId: Destruction complete after 0s
azurerm_network_interface_security_group_association.example: Destroying... [id=/subscriptions/765266c6-9a23-4638-af32-dd1e32613047/resourceGroups/devops-TP2/providers/Microsoft.Network/networkInterfaces/NIC-20200828|/subscriptions/765266c6-9a23-4638-af32-dd1e32613047/resourceGroups/devops-TP2/providers/Microsoft.Network/networkSecurityGroups/NetworkSecurityGroup-20200828]
azurerm_linux_virtual_machine.Devops-20200828: Destroying... [id=/subscriptions/765266c6-9a23-4638-af32-dd1e32613047/resourceGroups/devops-TP2/providers/Microsoft.Compute/virtualMachines/devops20200828]
azurerm_network_interface_security_group_association.example: Destruction complete after 6s
azurerm_network_security_group.myterraformnsg: Destroying... [id=/subscriptions/765266c6-9a23-4638-af32-dd1e32613047/resourceGroups/devops-TP2/providers/Microsoft.Network/networkSecurityGroups/NetworkSecurityGroup-20200828]
azurerm_linux_virtual_machine.Devops-20200828: Still destroying... [id=/subscriptions/765266c6-9a23-4638-af32-...Compute/virtualMachines/devops20200828, 10s elapsed]
azurerm_network_security_group.myterraformnsg: Still destroying... [id=/subscriptions/765266c6-9a23-4638-af32-...tyGroups/NetworkSecurityGroup-20200828, 10s elapsed]
azurerm_network_security_group.myterraformnsg: Destruction complete after 11s
azurerm_linux_virtual_machine.Devops-20200828: Still destroying... [id=/subscriptions/765266c6-9a23-4638-af32-...Compute/virtualMachines/devops20200828, 20s elapsed]
azurerm_linux_virtual_machine.Devops-20200828: Still destroying... [id=/subscriptions/765266c6-9a23-4638-af32-...Compute/virtualMachines/devops20200828, 30s elapsed]
azurerm_linux_virtual_machine.Devops-20200828: Still destroying... [id=/subscriptions/765266c6-9a23-4638-af32-...Compute/virtualMachines/devops20200828, 40s elapsed]
azurerm_linux_virtual_machine.Devops-20200828: Still destroying... [id=/subscriptions/765266c6-9a23-4638-af32-...Compute/virtualMachines/devops20200828, 50s elapsed]
azurerm_linux_virtual_machine.Devops-20200828: Still destroying... [id=/subscriptions/765266c6-9a23-4638-af32-...Compute/virtualMachines/devops20200828, 1m0s elapsed]
azurerm_linux_virtual_machine.Devops-20200828: Still destroying... [id=/subscriptions/765266c6-9a23-4638-af32-...Compute/virtualMachines/devops20200828, 1m10s elapsed]
azurerm_linux_virtual_machine.Devops-20200828: Destruction complete after 1m20s
azurerm_network_interface.myterraformnic: Destroying... [id=/subscriptions/765266c6-9a23-4638-af32-dd1e32613047/resourceGroups/devops-TP2/providers/Microsoft.Network/networkInterfaces/NIC-20200828]
tls_private_key.example_ssh: Destroying... [id=e9cc691ff5c8623884126a6a56ba2d971e944b57]
tls_private_key.example_ssh: Destruction complete after 0s
azurerm_network_interface.myterraformnic: Destruction complete after 5s
azurerm_public_ip.myterraformpublicip: Destroying... [id=/subscriptions/765266c6-9a23-4638-af32-dd1e32613047/resourceGroups/devops-TP2/providers/Microsoft.Network/publicIPAddresses/PublicIP-20200828]
azurerm_public_ip.myterraformpublicip: Still destroying... [id=/subscriptions/765266c6-9a23-4638-af32-...rk/publicIPAddresses/PublicIP-20200828, 10s elapsed]
azurerm_public_ip.myterraformpublicip: Destruction complete after 14s

Destroy complete! Resources: 7 destroyed.
```

### Pourquoi utiliser terraform

On évite de travailler manuellement, l’outils est automatique, utiliser l’infrastructure as code permet la modification et l’ajout facile de configurations. Si on a un cluster de plusieur VM, ça sera plus rapide et facile de les créer avec terraform et pour chaque modification c’est juste des bout de code de changer à la place de reconfigurer chaque machine manuellement.
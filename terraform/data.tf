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
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
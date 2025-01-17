variable "sysdig_secure_api_token" {
  sensitive   = true
  type        = string
  description = "Sysdig Secure API token"
}

#---------------------------------
# optionals - with defaults
#---------------------------------

#
# cloudtrail configuration
#

variable "cloudtrail_is_multi_region_trail" {
  type        = bool
  default     = true
  description = "true/false whether cloudtrail will ingest multiregional events. testing/economization purpose. "
}

variable "cloudtrail_kms_enable" {
  type        = bool
  default     = true
  description = "true/false whether s3 should be encrypted. testing/economization purpose."
}


#
# general
#
variable "region" {
  type        = string
  default     = "eu-central-1"
  description = "Default region for resource creation in both organization master and secure-for-cloud member account"
}

variable "name" {
  type        = string
  description = "Name for the Cloud Vision deployment"
  default     = "sysdig-secure-for-cloud-k8s"
}

variable "sysdig_secure_endpoint" {
  type        = string
  default     = "https://secure.sysdig.com"
  description = "Sysdig Secure API endpoint"
}

variable "tags" {
  type        = map(string)
  description = "sysdig secure-for-cloud tags"
  default = {
    "product" = "sysdig-secure-for-cloud"
  }
}

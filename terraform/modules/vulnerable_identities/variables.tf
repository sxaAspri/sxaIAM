variable "account_id" {
  description = "AWS account ID — used to build ARNs"
  type        = string
}

variable "name_prefix" {
  description = "Prefix for all IAM resource names"
  type        = string
}

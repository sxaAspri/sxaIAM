variable "aws_region" {
  description = "AWS region to deploy resources"
  type        = string
  default     = "us-east-1"
}

variable "aws_profile" {
  description = "AWS CLI profile to use"
  type        = string
  default     = "default"
}

variable "name_prefix" {
  description = "Prefix for all IAM resource names"
  type        = string
  default     = "sxaiam-test"
}

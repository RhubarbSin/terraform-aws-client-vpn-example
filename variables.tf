variable "region" {
  type    = string
  default = "us-east-2"
}

variable "name" {
  type    = string
  default = "AWS Client VPN"
}

variable "vpn_certificate_domain_name" {
  type    = string
  default = "vpn.example.com"

  validation {
    condition     = can(regex("^[a-z][a-z0-9\\.]*\\.[a-z]+$", var.vpn_certificate_domain_name))
    error_message = "The value of vpn_certificate_domain_name variable must be a valid DNS name."
  }
}

variable "ssm_parameter_name" {
  type = map(string)
  default = {
    client_vpn : "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-arm64",
    vpn_client : "/aws/service/canonical/ubuntu/server/22.04/stable/current/amd64/hvm/ebs-gp2/ami-id",
  }
}

variable "split_tunnel_mode" {
  type    = bool
  default = true
}

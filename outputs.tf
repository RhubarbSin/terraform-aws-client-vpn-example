output "client_vpn_instance_id" {
  value = aws_instance.this["client_vpn"].id
}

output "client_vpn_instance_private_ip" {
  value = aws_instance.this["client_vpn"].private_ip
}

output "vpn_client_instance_id" {
  value = aws_instance.this["vpn_client"].id
}

output "vpn_client_instance_public_ip" {
  value = aws_instance.this["vpn_client"].public_ip
}

output "client_vpn_configuration_file_url" {
  value = data.external.presigned_url["cvpn_config"].result.url
}

output "ssh_private_key_file_url" {
  value = data.external.presigned_url["ssh_private_key"].result.url
}

output "ssh_private_key_file_name" {
  value = basename(local_sensitive_file.this.filename)
}

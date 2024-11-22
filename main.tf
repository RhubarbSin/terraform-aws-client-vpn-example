provider "aws" {
  region = var.region

  default_tags {
    tags = { Name : var.name }
  }
}

resource "random_integer" "this" {
  min = "2886860800"
  max = "2887711488"
}

locals {
  bits              = format("%b", random_integer.this.result)
  octets            = [for n in range(0, 32, 8) : parseint(substr(local.bits, n, 8), 2)]
  ip_address        = join(".", local.octets)
  network_address   = cidrhost(format("%s/24", local.ip_address), 0)
  vpc_cidr_block    = format("%s/24", local.network_address)
  client_cidr_block = format("%s/22", cidrhost(format("%s/22", join(".", [for n in range(0, 32, 8) : parseint(substr(format("%b", random_integer.this.result + 1024), n, 8), 2)])), 0))
  vpc = {
    client_vpn : {
      name : "Client VPN",
      cidr_block : cidrsubnet(local.vpc_cidr_block, 1, 0),
      map_public_ip_on_launch : false,
    },
    vpn_client : {
      name : "VPN Client",
      cidr_block : cidrsubnet(local.vpc_cidr_block, 1, 1),
      map_public_ip_on_launch : true,
    },
  }
}

resource "aws_vpc" "this" {
  for_each = local.vpc

  cidr_block           = each.value.cidr_block
  enable_dns_hostnames = true

  tags = { Name : each.value.name }
}

resource "aws_default_security_group" "this" {
  for_each = aws_vpc.this

  vpc_id = each.value.id

  tags = { Name : "${each.value.tags.Name} Default" }
}

resource "aws_vpc_security_group_egress_rule" "default" {
  for_each = aws_default_security_group.this

  security_group_id = each.value.id

  cidr_ipv4   = "0.0.0.0/0"
  ip_protocol = -1
}

resource "aws_default_route_table" "this" {
  for_each = aws_vpc.this

  default_route_table_id = each.value.default_route_table_id
}

resource "aws_internet_gateway" "this" {
  for_each = aws_vpc.this
}

resource "aws_internet_gateway_attachment" "this" {
  for_each = aws_internet_gateway.this

  internet_gateway_id = each.value.id
  vpc_id              = aws_vpc.this[each.key].id
}

resource "aws_route" "this" {
  for_each = aws_default_route_table.this

  route_table_id         = each.value.id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_internet_gateway.this[each.key].id

  depends_on = [aws_internet_gateway_attachment.this]
}

data "aws_availability_zones" "this" {
  state = "available"
}

resource "random_shuffle" "this" {
  input = data.aws_availability_zones.this.names

  result_count = 1
}

resource "aws_subnet" "this" {
  for_each = aws_vpc.this

  vpc_id = each.value.id

  cidr_block                          = each.value.cidr_block
  availability_zone                   = one(random_shuffle.this.result)
  map_public_ip_on_launch             = local.vpc[each.key].map_public_ip_on_launch
  private_dns_hostname_type_on_launch = "resource-name"
}

resource "aws_route_table_association" "this" {
  for_each = aws_default_route_table.this

  route_table_id = each.value.id
  subnet_id      = aws_subnet.this[each.key].id
}

resource "aws_security_group" "cvpn" {
  name        = "${aws_vpc.this["client_vpn"].tags.Name} CVPN"
  description = "${aws_vpc.this["client_vpn"].tags.Name} CVPN"
  vpc_id      = aws_vpc.this["client_vpn"].id

  tags = { Name : "${aws_vpc.this["client_vpn"].tags.Name} CVPN" }

  lifecycle {
    create_before_destroy = false
  }
}

resource "aws_vpc_security_group_ingress_rule" "cvpn_ec2_all" {
  security_group_id = aws_security_group.ec2["client_vpn"].id

  referenced_security_group_id = aws_security_group.cvpn.id
  ip_protocol                  = -1
  description                  = "Client VPN"

  tags = { Name : "Client VPN" }

  lifecycle {
    create_before_destroy = false
  }
}

resource "aws_security_group" "ec2" {
  for_each = aws_vpc.this

  name        = "${each.value.tags.Name} EC2"
  description = "${each.value.tags.Name} EC2"
  vpc_id      = each.value.id

  tags = { Name : "${each.value.tags.Name} EC2" }

  lifecycle {
    create_before_destroy = false
  }
}

resource "aws_vpc_security_group_ingress_rule" "all_ec2_tcp_22" {
  security_group_id = aws_security_group.ec2["vpn_client"].id

  cidr_ipv4   = "0.0.0.0/0"
  ip_protocol = "tcp"
  from_port   = 22
  to_port     = 22
  description = "All"

  tags = { Name : "All" }

  lifecycle {
    create_before_destroy = false
  }
}

resource "aws_security_group" "vpce" {
  for_each = aws_vpc.this

  name        = "${each.value.tags.Name} VPCE"
  description = "${each.value.tags.Name} VPCE"
  vpc_id      = each.value.id

  tags = { Name : "${each.value.tags.Name} VPCE" }

  lifecycle {
    create_before_destroy = false
  }
}

resource "aws_vpc_security_group_ingress_rule" "vpc_vpce_tcp_443" {
  for_each = aws_vpc.this

  security_group_id = aws_security_group.vpce[each.key].id

  cidr_ipv4   = each.value.cidr_block
  ip_protocol = "tcp"
  from_port   = 443
  to_port     = 443
  description = "VPC Internal"

  tags = { Name : "VPC Internal" }

  lifecycle {
    create_before_destroy = false
  }
}

locals {
  vpc_endpoint = {
    ssm = {
      type = "Interface",
      name = "SSM",
    },
    ssmmessages = {
      type = "Interface",
      name = "SSM Messages",
    },
    s3 = {
      type = "Gateway",
      name = "S3 Gateway",
    },
  }
}

resource "aws_vpc_endpoint" "this" {
  for_each = {
    for tuple in setproduct(keys(aws_vpc.this), keys(local.vpc_endpoint)) :
    "${tuple.0}_${tuple.1}" => {
      vpc_key          = tuple.0,
      vpc_endpoint_key = tuple.1,
    }
  }

  service_name = "com.amazonaws.${var.region}.${each.value.vpc_endpoint_key}"
  vpc_id       = aws_vpc.this[each.value.vpc_key].id

  private_dns_enabled = local.vpc_endpoint[each.value.vpc_endpoint_key].type == "Interface" ? true : false
  vpc_endpoint_type   = local.vpc_endpoint[each.value.vpc_endpoint_key].type

  tags = {
    Name : "${aws_vpc.this[each.value.vpc_key].tags.Name} ${local.vpc_endpoint[each.value.vpc_endpoint_key].name}"
  }
}

resource "aws_vpc_endpoint_security_group_association" "this" {
  for_each = {
    for k, v in aws_vpc_endpoint.this :
    k => v if v.vpc_endpoint_type == "Interface"
  }

  vpc_endpoint_id   = each.value.id
  security_group_id = one([for sg in aws_security_group.vpce : sg if sg.vpc_id == each.value.vpc_id]).id
}

resource "aws_vpc_endpoint_subnet_association" "this" {
  for_each = {
    for k, v in aws_vpc_endpoint.this :
    k => v if v.vpc_endpoint_type == "Interface"
  }

  vpc_endpoint_id = each.value.id
  subnet_id       = one([for subnet in aws_subnet.this : subnet if subnet.vpc_id == each.value.vpc_id]).id
}

resource "aws_vpc_endpoint_route_table_association" "this" {
  for_each = {
    for k, v in aws_vpc_endpoint.this :
    k => v if v.vpc_endpoint_type == "Gateway"
  }

  vpc_endpoint_id = each.value.id
  route_table_id  = one([for rtb in aws_default_route_table.this : rtb if rtb.vpc_id == each.value.vpc_id]).id
}

data "aws_partition" "this" {}

resource "aws_acmpca_certificate_authority" "this" {
  for_each = toset(["root", "intermediate", "signing"])

  type                            = each.key == "root" ? "ROOT" : "SUBORDINATE"
  permanent_deletion_time_in_days = 7

  certificate_authority_configuration {
    key_algorithm     = "RSA_4096"
    signing_algorithm = "SHA512WITHRSA"

    subject {
      common_name = title(each.key)
    }
  }
}

resource "aws_acmpca_permission" "this" {
  for_each = aws_acmpca_certificate_authority.this

  certificate_authority_arn = each.value.arn
  actions = [
    "IssueCertificate",
    "GetCertificate",
    "ListPermissions",
  ]
  principal = "acm.amazonaws.com"
}

resource "aws_acmpca_certificate" "root" {
  certificate_authority_arn   = aws_acmpca_certificate_authority.this["root"].arn
  certificate_signing_request = aws_acmpca_certificate_authority.this["root"].certificate_signing_request
  signing_algorithm           = "SHA512WITHRSA"

  validity {
    type  = "YEARS"
    value = 15
  }

  template_arn = "arn:${data.aws_partition.this.partition}:acm-pca:::template/RootCACertificate/V1"
}

resource "aws_acmpca_certificate_authority_certificate" "root" {
  certificate               = aws_acmpca_certificate.root.certificate
  certificate_authority_arn = aws_acmpca_certificate_authority.this["root"].arn
}

resource "aws_acmpca_certificate" "intermediate" {
  certificate_authority_arn   = aws_acmpca_certificate_authority.this["root"].arn
  certificate_signing_request = aws_acmpca_certificate_authority.this["intermediate"].certificate_signing_request
  signing_algorithm           = "SHA512WITHRSA"

  validity {
    type  = "YEARS"
    value = 10
  }

  template_arn = "arn:${data.aws_partition.this.partition}:acm-pca:::template/SubordinateCACertificate_PathLen1/V1"
}

resource "aws_acmpca_certificate_authority_certificate" "intermediate" {
  certificate               = aws_acmpca_certificate.intermediate.certificate
  certificate_authority_arn = aws_acmpca_certificate_authority.this["intermediate"].arn

  certificate_chain = aws_acmpca_certificate.intermediate.certificate_chain
}

resource "aws_acmpca_certificate" "signing" {
  certificate_authority_arn   = aws_acmpca_certificate_authority.this["intermediate"].arn
  certificate_signing_request = aws_acmpca_certificate_authority.this["signing"].certificate_signing_request
  signing_algorithm           = "SHA512WITHRSA"

  validity {
    type  = "YEARS"
    value = 5
  }

  template_arn = "arn:${data.aws_partition.this.partition}:acm-pca:::template/SubordinateCACertificate_PathLen0/V1"
}

resource "aws_acmpca_certificate_authority_certificate" "signing" {
  certificate               = aws_acmpca_certificate.signing.certificate
  certificate_authority_arn = aws_acmpca_certificate_authority.this["signing"].arn

  certificate_chain = aws_acmpca_certificate.signing.certificate_chain
}

resource "aws_acm_certificate" "cvpn" {
  certificate_authority_arn = aws_acmpca_certificate_authority.this["signing"].arn
  domain_name               = var.vpn_certificate_domain_name

  early_renewal_duration = "P60D"

  lifecycle {
    create_before_destroy = true
  }

  depends_on = [aws_acmpca_certificate_authority_certificate.signing]
}

resource "tls_private_key" "user" {
  algorithm = "RSA"
}

resource "tls_cert_request" "user" {
  private_key_pem = tls_private_key.user.private_key_pem

  subject {
    common_name = "user"
  }
}

resource "aws_acmpca_certificate" "user" {
  certificate_authority_arn   = aws_acmpca_certificate_authority.this["signing"].arn
  certificate_signing_request = tls_cert_request.user.cert_request_pem
  signing_algorithm           = "SHA512WITHRSA"

  validity {
    type  = "YEARS"
    value = 1
  }
}

resource "aws_ec2_client_vpn_endpoint" "this" {
  client_cidr_block      = local.client_cidr_block
  server_certificate_arn = aws_acm_certificate.cvpn.arn

  vpc_id = aws_vpc.this["client_vpn"].id
  security_group_ids = [
    aws_security_group.cvpn.id,
    aws_default_security_group.this["client_vpn"].id,
  ]
  split_tunnel = var.split_tunnel_mode

  authentication_options {
    type                       = "certificate-authentication"
    root_certificate_chain_arn = aws_acm_certificate.cvpn.arn
  }

  connection_log_options {
    enabled = false
  }
}

resource "aws_ec2_client_vpn_network_association" "this" {
  client_vpn_endpoint_id = aws_ec2_client_vpn_endpoint.this.id
  subnet_id              = aws_subnet.this["client_vpn"].id
}

locals {
  authorization_rule = merge(
    {
      private : {
        cidr_block : aws_subnet.this["client_vpn"].cidr_block,
        description : "VPC Subnet",
      }
    },
    var.split_tunnel_mode ?
    {} :
    {
      public : {
        cidr_block : "0.0.0.0/0",
        description : "Internet",
      }
    }
  )
}

resource "aws_ec2_client_vpn_authorization_rule" "this" {
  for_each = local.authorization_rule

  client_vpn_endpoint_id = aws_ec2_client_vpn_endpoint.this.id
  target_network_cidr    = each.value.cidr_block
  description            = each.value.description

  authorize_all_groups = true

  lifecycle {
    create_before_destroy = false
  }
}

resource "aws_ec2_client_vpn_route" "this" {
  count = var.split_tunnel_mode ? 0 : 1

  client_vpn_endpoint_id = aws_ec2_client_vpn_endpoint.this.id
  target_vpc_subnet_id   = aws_subnet.this["client_vpn"].id
  destination_cidr_block = "0.0.0.0/0"
  description            = "Internet"

  timeouts {
    create = "20m"
    delete = "20m"
  }
}

data "external" "file" {
  program = ["bash", "${path.module}/client-config.sh"]

  query = {
    region : var.region,
    client_vpn_endpoint_id : aws_ec2_client_vpn_endpoint.this.id,
  }
}

locals {
  cvpn_config = templatefile(
    "${path.module}/client-config.tftpl",
    {
      configuration : data.external.file.result.ClientConfiguration,
      certificate : aws_acmpca_certificate.user.certificate,
      certificate_chain : aws_acmpca_certificate.user.certificate_chain,
      private_key : tls_private_key.user.private_key_pem,
    }
  )
}

resource "tls_private_key" "ssh" {
  algorithm = "ED25519"
}

resource "random_pet" "this" {}

resource "local_sensitive_file" "this" {
  filename = "${path.module}/${random_pet.this.id}"

  content         = tls_private_key.ssh.private_key_openssh
  file_permission = "0600"
}

resource "aws_s3_bucket" "this" {
  force_destroy = true
}

resource "aws_s3_object" "this" {
  for_each = {
    cvpn_config : {
      key : "client-config.ovpn",
      content : local.cvpn_config,
    },
    ssh_private_key : {
      key : random_pet.this.id,
      content : tls_private_key.ssh.private_key_openssh,
    },
  }

  bucket  = aws_s3_bucket.this.id
  key     = each.value.key
  content = each.value.content
}

data "external" "presigned_url" {
  for_each = aws_s3_object.this

  program = ["bash", "${path.module}/presigned-url.sh"]

  query = {
    region : var.region,
    s3_uri : "s3://${aws_s3_bucket.this.id}/${each.value.key}",
  }
}

data "aws_iam_policy_document" "this" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "this" {
  assume_role_policy = data.aws_iam_policy_document.this.json

  name = replace(var.name, " ", "-")
}

data "aws_iam_policy" "this" {
  name = "AmazonSSMManagedInstanceCore"
}

resource "aws_iam_role_policy_attachment" "this" {
  role       = aws_iam_role.this.name
  policy_arn = data.aws_iam_policy.this.arn
}

resource "aws_iam_instance_profile" "this" {
  name = replace(var.name, " ", "-")
  role = aws_iam_role.this.name
}

resource "aws_key_pair" "this" {
  key_name   = random_pet.this.id
  public_key = tls_private_key.ssh.public_key_openssh
}

data "aws_ssm_parameter" "this" {
  name = var.ssm_parameter_name

  with_decryption = false
}

data "aws_ami" "this" {
  filter {
    name   = "image-id"
    values = [data.aws_ssm_parameter.this.value]
  }
}

data "aws_ec2_instance_types" "this" {
  filter {
    name   = "burstable-performance-supported"
    values = ["true"]
  }

  filter {
    name   = "current-generation"
    values = ["true"]
  }

  filter {
    name   = "memory-info.size-in-mib"
    values = ["512"]
  }

  filter {
    name   = "processor-info.supported-architecture"
    values = [data.aws_ami.this.architecture]
  }
}

locals {
  ssh_config = <<-EOF
    StrictHostKeyChecking no
    IdentityFile ~/.ssh/${random_pet.this.id}
    User ec2-user
    EOF
  user_data = {
    client_vpn : {
      repo_update : true,
      repo_upgrade : "all",
    },
    vpn_client : {
      repo_update : true,
      repo_upgrade : "all",
      packages : "openvpn",
      write_files : [
        {
          path : "/home/ec2-user/.ssh/${random_pet.this.id}",
          permissions : "0600",
          owner : "ec2-user:ec2-user",
          content : tls_private_key.ssh.private_key_openssh,
          defer : true,
        },
        {
          path : "/home/ec2-user/.ssh/config",
          permissions : "0600",
          owner : "ec2-user:ec2-user",
          content : local.ssh_config,
          defer : true,
        },
        {
          path : "/etc/openvpn/client/aws-client-vpn.conf",
          permissions : "0600",
          content : local.cvpn_config,
          defer : true,
        },
      ],
      runcmd : [
        "systemctl enable openvpn-client@aws-client-vpn",
        "systemctl start openvpn-client@aws-client-vpn",
      ],
    },
  }
}

data "cloudinit_config" "this" {
  for_each = local.user_data

  part {
    content = yamlencode(each.value)

    content_type = "text/cloud-config"
  }
}

resource "aws_instance" "this" {
  for_each = data.cloudinit_config.this

  ami                  = data.aws_ssm_parameter.this.value
  iam_instance_profile = aws_iam_role.this.name
  instance_type        = data.aws_ec2_instance_types.this.instance_types.0
  key_name             = aws_key_pair.this.key_name
  subnet_id            = aws_subnet.this[each.key].id
  user_data            = each.value.rendered
  volume_tags          = { Name : aws_vpc.this[each.key].tags.Name }
  vpc_security_group_ids = [
    aws_security_group.ec2[each.key].id,
    aws_default_security_group.this[each.key].id,
  ]

  root_block_device {
    encrypted   = true
    volume_type = "gp3"
  }

  tags = { Name : aws_vpc.this[each.key].tags.Name }

  depends_on = [
    aws_vpc_endpoint_route_table_association.this,
    aws_ec2_client_vpn_authorization_rule.this,
    aws_ec2_client_vpn_network_association.this,
  ]
}

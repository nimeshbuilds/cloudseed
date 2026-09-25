locals {
  az_count  = length(var.azs)
  nat_count = var.single_nat_gateway ? 1 : local.az_count
  # Subnet blocks (cidrsubnet numbers) per tier: [public, private, data][AZ]. The first `stride` AZs use the original
  # layout (public 0.., private stride.., data 2*stride..); every AZ after them gets the next three blocks. With the
  # stride pinned to the AZ count of the first deployment, adding or removing an AZ never moves an existing subnet
  # (a changed cidr_block replaces the subnet and everything in it). The data block is reserved even without a data
  # tier, so switching create_data_subnets never moves anything either.
  stride = var.subnet_stride != null ? var.subnet_stride : local.az_count
  blocks = [for tier in range(3) : [for i in range(local.az_count) :
  i < local.stride ? tier * local.stride + i : 3 * local.stride + 3 * (i - local.stride) + tier]]
}

resource "aws_vpc" "this" {
  cidr_block           = var.vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true
  tags                 = merge(var.tags, { Name = "${var.prefix}-vpc" })
}

# Lock down the default security group: no rules at all.
resource "aws_default_security_group" "this" {
  vpc_id = aws_vpc.this.id
  tags   = merge(var.tags, { Name = "${var.prefix}-default-locked" })
}

resource "aws_internet_gateway" "this" {
  vpc_id = aws_vpc.this.id
  tags   = merge(var.tags, { Name = "${var.prefix}-igw" })
}

# ---- Subnets ----
resource "aws_subnet" "public" {
  count = local.az_count

  vpc_id                  = aws_vpc.this.id
  cidr_block              = cidrsubnet(var.vpc_cidr, var.subnet_newbits, local.blocks[0][count.index])
  availability_zone       = var.azs[count.index]
  map_public_ip_on_launch = false
  # kubernetes.io/role/*: the subnets Kubernetes load balancers go into. The EKS cloud controller and the AWS Load
  # Balancer Controller pick internet-facing ones from the elb-tagged (public) subnets and internal ones from the
  # internal-elb-tagged (private) subnets; untagged, an internal NLB could land in any subnet of an AZ.
  tags = merge(var.tags, {
    Name                     = "${var.prefix}-public-${var.azs[count.index]}"
    Tier                     = "public"
    "kubernetes.io/role/elb" = "1"
  })
}

resource "aws_subnet" "private" {
  count = local.az_count

  vpc_id            = aws_vpc.this.id
  cidr_block        = cidrsubnet(var.vpc_cidr, var.subnet_newbits, local.blocks[1][count.index])
  availability_zone = var.azs[count.index]
  tags = merge(var.tags, {
    Name                              = "${var.prefix}-private-${var.azs[count.index]}"
    Tier                              = "private"
    "kubernetes.io/role/internal-elb" = "1"
  })
}

resource "aws_subnet" "data" {
  count = var.create_data_subnets ? local.az_count : 0

  vpc_id            = aws_vpc.this.id
  cidr_block        = cidrsubnet(var.vpc_cidr, var.subnet_newbits, local.blocks[2][count.index])
  availability_zone = var.azs[count.index]
  tags              = merge(var.tags, { Name = "${var.prefix}-data-${var.azs[count.index]}", Tier = "data" })
}

# ---- NAT ----
resource "aws_eip" "nat" {
  count  = local.nat_count
  domain = "vpc"
  tags   = merge(var.tags, { Name = "${var.prefix}-nat-${count.index}" })
}

resource "aws_nat_gateway" "this" {
  count = local.nat_count

  allocation_id = aws_eip.nat[count.index].id
  subnet_id     = aws_subnet.public[count.index].id
  tags          = merge(var.tags, { Name = "${var.prefix}-nat-${var.azs[count.index]}" })

  depends_on = [aws_internet_gateway.this]
}

# ---- Routing ----
resource "aws_route_table" "public" {
  vpc_id = aws_vpc.this.id
  tags   = merge(var.tags, { Name = "${var.prefix}-public" })
}

resource "aws_route" "public_internet" {
  route_table_id         = aws_route_table.public.id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_internet_gateway.this.id
}

resource "aws_route_table_association" "public" {
  count          = local.az_count
  subnet_id      = aws_subnet.public[count.index].id
  route_table_id = aws_route_table.public.id
}

resource "aws_route_table" "private" {
  count  = local.az_count
  vpc_id = aws_vpc.this.id
  tags   = merge(var.tags, { Name = "${var.prefix}-private-${var.azs[count.index]}" })
}

resource "aws_route" "private_nat" {
  count                  = local.az_count
  route_table_id         = aws_route_table.private[count.index].id
  destination_cidr_block = "0.0.0.0/0"
  nat_gateway_id         = aws_nat_gateway.this[var.single_nat_gateway ? 0 : count.index].id
}

resource "aws_route_table_association" "private" {
  count          = local.az_count
  subnet_id      = aws_subnet.private[count.index].id
  route_table_id = aws_route_table.private[count.index].id
}

# Data tier: local routes only, no internet path in either direction.
resource "aws_route_table" "data" {
  count  = var.create_data_subnets ? 1 : 0
  vpc_id = aws_vpc.this.id
  tags   = merge(var.tags, { Name = "${var.prefix}-data" })
}

resource "aws_route_table_association" "data" {
  count          = var.create_data_subnets ? local.az_count : 0
  subnet_id      = aws_subnet.data[count.index].id
  route_table_id = aws_route_table.data[0].id
}

# ---- Flow logs ----
resource "aws_cloudwatch_log_group" "flow" {
  count = var.enable_flow_logs ? 1 : 0

  name              = "/cloudseed/${var.prefix}/vpc-flow-logs"
  retention_in_days = var.flow_log_retention_days
  kms_key_id        = var.kms_key_arn
  tags              = var.tags
}

data "aws_iam_policy_document" "flow_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["vpc-flow-logs.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "flow" {
  count = var.enable_flow_logs ? 1 : 0

  name               = "${var.prefix}-vpc-flow-logs"
  assume_role_policy = data.aws_iam_policy_document.flow_assume.json
  tags               = var.tags
}

data "aws_iam_policy_document" "flow" {
  count = var.enable_flow_logs ? 1 : 0

  statement {
    actions = [
      "logs:CreateLogStream",
      "logs:PutLogEvents",
      "logs:DescribeLogGroups",
      "logs:DescribeLogStreams",
    ]
    resources = ["${aws_cloudwatch_log_group.flow[0].arn}:*"]
  }
}

resource "aws_iam_role_policy" "flow" {
  count = var.enable_flow_logs ? 1 : 0

  name   = "vpc-flow-logs"
  role   = aws_iam_role.flow[0].id
  policy = data.aws_iam_policy_document.flow[0].json
}

resource "aws_flow_log" "this" {
  count = var.enable_flow_logs ? 1 : 0

  vpc_id                   = aws_vpc.this.id
  traffic_type             = "ALL"
  log_destination_type     = "cloud-watch-logs"
  log_destination          = aws_cloudwatch_log_group.flow[0].arn
  iam_role_arn             = aws_iam_role.flow[0].arn
  max_aggregation_interval = 60
  tags                     = merge(var.tags, { Name = "${var.prefix}-flow-log" })
}

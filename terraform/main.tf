
variable "aws_regions" {
  description = "AWS Regions for multi-region deployment"
  type        = list(string)
  default     = ["us-east-1", "ap-south-1"]
}

provider "aws" {
  alias  = "primary"
  region = var.aws_regions[0]
}

provider "aws" {
  alias  = "secondary"
  region = var.aws_regions[1]
}


# ---------------------- VPCs ----------------------
resource "aws_vpc" "main_us_east" {
  provider   = aws.primary
  cidr_block = "10.0.0.0/16"
  tags = {
    Name = "Multi-Tenant-VPC-us-east-1"
  }
}

resource "aws_vpc" "main_ap_south" {
  provider   = aws.secondary
  cidr_block = "10.0.0.0/16"
  tags = {
    Name = "Multi-Tenant-VPC-ap-south-1"
  }
}


# ---------------------- Public Subnets ----------------------

# Public Subnet in us-east-1
resource "aws_subnet" "public_us_east" {
  provider                = aws.primary
  vpc_id                  = aws_vpc.main_us_east.id
  cidr_block              = "10.0.1.0/24"
  map_public_ip_on_launch = true
  availability_zone       = "us-east-1a"
}

# Public Subnet in ap-south-1
resource "aws_subnet" "public_ap_south" {
  provider                = aws.secondary
  vpc_id                  = aws_vpc.main_ap_south.id
  cidr_block              = "10.0.3.0/24"
  map_public_ip_on_launch = true
  availability_zone       = "ap-south-1a"
}

# ---------------------- Private Subnets ----------------------

# Private Subnet in us-east-1
resource "aws_subnet" "private_us_east" {
  provider          = aws.primary
  vpc_id            = aws_vpc.main_us_east.id
  cidr_block        = "10.0.5.0/24"
  availability_zone = "us-east-1a"
}

# Private Subnet in ap-south-1
resource "aws_subnet" "private_ap_south" {
  provider          = aws.secondary
  vpc_id            = aws_vpc.main_ap_south.id
  cidr_block        = "10.0.7.0/24"
  availability_zone = "ap-south-1a"
}

resource "aws_subnet" "private_us_east_2" {
  provider          = aws.primary
  vpc_id            = aws_vpc.main_us_east.id
  cidr_block        = "10.0.6.0/24"
  availability_zone = "us-east-1b"
}

resource "aws_subnet" "private_ap_south_2" {
  provider          = aws.secondary
  vpc_id            = aws_vpc.main_ap_south.id
  cidr_block        = "10.0.8.0/24"
  availability_zone = "ap-south-1b"
}

resource "aws_db_subnet_group" "us_east" {
  provider    = aws.primary
  name        = "us-east-subnet-group"
  subnet_ids  = [aws_subnet.private_us_east.id, aws_subnet.private_us_east_2.id]
  description = "DB subnet group for us-east-1"
}

resource "aws_db_subnet_group" "ap_south" {
  provider    = aws.secondary
  name        = "ap-south-subnet-group"
  subnet_ids  = [aws_subnet.private_ap_south.id, aws_subnet.private_ap_south_2.id]
  description = "DB subnet group for ap-south-1"
}



# ---------------------- IAM Role with Tenant Access Controls ----------------------
resource "aws_iam_role" "tenant_access" {
  provider = aws.primary
  name     = "tenant_access_role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        AWS = ["arn:aws:iam::471112954554:root"]
      }
      Action = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_policy" "tenant_data_restriction" {
  provider    = aws.primary
  name        = "TenantDataRestrictionPolicy"
  description = "Restrict tenants to their own data."
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Deny"
      Action   = ["s3:PutObject", "rds:CreateDBInstance"]
      Resource = "*"
      Condition = {
        StringNotEqualsIfExists = {
          "aws:RequestedRegion" : ["us-east-1", "ap-south-1"]
        }
      }
    }]
  })
}

# ---------------------- Automated Backup & Restore ----------------------
resource "aws_db_snapshot" "daily_backup_us_east" {
  provider               = aws.primary
  db_instance_identifier = aws_db_instance.postgres_us_east.id
  db_snapshot_identifier = "daily-snapshot-us-east-${formatdate("YYYYMMDD-HHmmss", timestamp())}"
}

resource "aws_db_snapshot" "daily_backup_ap_south" {
  provider               = aws.secondary
  db_instance_identifier = aws_db_instance.postgres_ap_south.id
  db_snapshot_identifier = "daily-snapshot-ap-south-${formatdate("YYYYMMDD-HHmmss", timestamp())}"
}

resource "aws_s3_bucket_lifecycle_configuration" "backup_policy" {
  provider = aws.primary
  bucket   = aws_s3_bucket.bbackup_bucket.id
  rule {
    id     = "backup-retention"
    status = "Enabled"
    expiration {
      days = 30
    }
  }
}

# ---------------------- GDPR & CCPA Compliance Strengthening ----------------------
resource "aws_organizations_policy" "data_residency_policy" {
  provider    = aws.primary
  name        = "DataResidencyPolicy"
  description = "Stricter region-based storage enforcement"
  content = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Deny"
      Action   = ["s3:PutObject", "rds:CreateDBInstance"]
      Resource = "*"
      Condition = {
        StringNotEqualsIfExists = {
          "aws:RequestedRegion" : ["ap-south-1", "us-east-1"]
        }
      }
    }]
  })
}

# ---------------------- Outputs ----------------------
output "eks_cluster_id" {
  value = aws_eks_cluster.eks.id
}

output "db_endpoint_us_east" {
  value     = aws_db_instance.postgres_us_east.endpoint
  sensitive = true
}

output "db_endpoint_ap_south" {
  value     = aws_db_instance.postgres_ap_south.endpoint
  sensitive = true
}

# ---------------------- IAM Role for EKS ----------------------

resource "aws_iam_role" "eks_cluster_role" {
  provider = aws.primary
  name     = "eks_cluster_role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "eks.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "eks_cluster" {
  provider   = aws.primary
  role       = aws_iam_role.eks_cluster_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
}

# ---------------------- EKS Cluster ----------------------

resource "aws_eks_cluster" "eks" {
  provider = aws.primary
  name     = "multi-tenant-cluster"
  role_arn = aws_iam_role.eks_cluster_role.arn

  vpc_config {
    subnet_ids = [
      aws_subnet.public_us_east.id,
      aws_subnet.private_us_east.id,
      aws_subnet.private_us_east_2.id # Add second AZ
    ]
  }

  depends_on = [
    aws_iam_role_policy_attachment.eks_cluster
  ]
}



# ---------------------- RDS with Multi-Region Read Replica ----------------------

# Update the RDS instances
resource "aws_db_instance" "postgres_us_east" {
  provider             = aws.primary
  identifier           = "multi-tenant-db-us-east"
  allocated_storage    = 20
  engine               = "postgres"
  instance_class       = "db.t3.micro"
  username             = "postgres"
  password             = "cPcjxXlkV3GT9nB"
  skip_final_snapshot  = true
  multi_az             = true
  storage_encrypted    = true
  kms_key_id           = aws_kms_key.db_encryption_us_east.arn
  db_subnet_group_name = aws_db_subnet_group.us_east.name
  # Remove availability_zone since multi_az is true
  # Remove map_public_ip_on_launch as it's not valid for RDS
}

resource "aws_db_instance" "postgres_ap_south" {
  provider             = aws.secondary
  identifier           = "multi-tenant-db-ap-south"
  allocated_storage    = 20
  engine               = "postgres"
  instance_class       = "db.t3.micro"
  username             = "postgres"
  password             = "cPcjxXlkV3GT9nB"
  skip_final_snapshot  = true
  multi_az             = true
  storage_encrypted    = true
  kms_key_id           = aws_kms_key.db_encryption_ap_south.arn
  db_subnet_group_name = aws_db_subnet_group.ap_south.name
  # Remove availability_zone since multi_az is true
  # Remove map_public_ip_on_launch as it's not valid for RDS
}

# ---------------------- Security & Logging ----------------------

resource "aws_cloudwatch_log_group" "eks_logs" {
  provider          = aws.primary
  name              = "/aws/eks/${aws_eks_cluster.eks.name}/cluster"
  retention_in_days = 30
}

resource "aws_kms_key" "db_encryption_us_east" {
  provider            = aws.primary
  description         = "KMS key for RDS encryption"
  enable_key_rotation = true
}

resource "aws_kms_key" "db_encryption_ap_south" {
  provider            = aws.secondary
  description         = "KMS key for RDS encryption"
  enable_key_rotation = true
}

# ---------------------- S3 Multi-Region Backup ----------------------


resource "aws_s3_bucket" "bbackup_bucket" {
  provider = aws.primary
  bucket   = "multi-tenant-backup-spikereach-2024" # Changed bucket name
  versioning { enabled = true }
}

resource "aws_s3_bucket" "bbackup_bucket_secondary" {
  provider = aws.secondary
  bucket   = "multi-tenant-backup-eu-spikereach-2024" # Changed bucket name
  versioning { enabled = true }
}

resource "aws_s3_bucket_versioning" "bbackup_versioning" {
  provider = aws.primary
  bucket   = aws_s3_bucket.bbackup_bucket.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_versioning" "bbackup_versioning_secondary" {
  provider = aws.secondary
  bucket   = aws_s3_bucket.bbackup_bucket_secondary.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_iam_role" "s3_replication_role" {
  provider = aws.primary
  name     = "s3_replication_role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "s3.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_policy" "s3_replication_policy" {
  provider = aws.primary
  name     = "s3_replication_policy"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = ["s3:ReplicateObject",
        "s3:ReplicateDelete",
        "s3:ReplicateTags",
        "s3:GetObjectVersionForReplication",
        "s3:GetObjectVersionAcl",
        "s3:GetObjectVersionTagging",
      "s3:ListBucket"]
      Resource = [
        aws_s3_bucket.bbackup_bucket.arn,
        "${aws_s3_bucket.bbackup_bucket.arn}/*",
        aws_s3_bucket.bbackup_bucket_secondary.arn,
        "${aws_s3_bucket.bbackup_bucket_secondary.arn}/*"
      ]
    }]
  })
}

resource "aws_iam_role_policy_attachment" "s3_replication_attach" {
  provider   = aws.primary
  role       = aws_iam_role.s3_replication_role.name
  policy_arn = aws_iam_policy.s3_replication_policy.arn
}


# ---------------------- Route 53 Latency-Based Routing ----------------------

resource "aws_route53_record" "api_record" {
  provider       = aws.primary
  zone_id        = "Z01246172L49BV8JDL1AY" # Replace with your actual Route 53 zone ID
  name           = "add.spikereach.com"
  type           = "A"
  ttl            = 300
  records        = ["98.81.7.50"]
  set_identifier = "us-east-1-primary"
  #  alias{
  #    name                     =
  #    zone_id                  = 
  #    evaluate_target_health   = true
  # }

  latency_routing_policy {
    region = "us-east-1"
  }
}

# ---------------------- CloudTrail for Compliance Monitoring ----------------------

resource "aws_s3_bucket_policy" "cloudtrail_s3_policy" {
  provider = aws.primary
  bucket   = aws_s3_bucket.bbackup_bucket.id
  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Effect    = "Allow",
      Principal = { Service = "cloudtrail.amazonaws.com" },
      Action    = "s3:PutObject",
      Resource  = "${aws_s3_bucket.bbackup_bucket.arn}/AWSLogs/*",
      Condition = {
        StringEquals = { "s3:x-amz-acl" : "bucket-owner-full-control" }
      }
    }]
  })
}

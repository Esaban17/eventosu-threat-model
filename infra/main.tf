# Configuración de la práctica. Solo se analiza estáticamente.
terraform {
  required_providers {
    aws = {
      source = "hashicorp/aws"
    }
  }
}

resource "aws_s3_bucket" "evidencias" {
  bucket = "eventosu-demo-evidencias-iac"
  tags = {
    Owner = "EventosU"
  }
}

resource "aws_s3_bucket_public_access_block" "evidencias" {
  bucket                  = aws_s3_bucket.evidencias.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "evidencias" {
  bucket = aws_s3_bucket.evidencias.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "evidencias" {
  bucket = aws_s3_bucket.evidencias.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "aws:kms"
    }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "evidencias" {
  bucket = aws_s3_bucket.evidencias.id

  rule {
    id     = "abortar-cargas-incompletas"
    status = "Enabled"

    filter {}

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }
}

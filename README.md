# vault-init

This is a mashup of [Seth Vargo's vault-init](https://github.com/sethvargo/vault-init) and [qntfy's vault-init-aws](https://github.com/qntfy/vault-init-aws/).

The `vault-init` service automates the process of [initializing](https://www.vaultproject.io/docs/commands/operator/init.html) and [unsealing](https://www.vaultproject.io/docs/concepts/seal.html#unsealing) HashiCorp Vault instances running on [Amazon Web Services](http://aws.amazon.com/).

After `vault-init` initializes a Vault server it stores master keys and root tokens, encrypted using [AWS Key Management Service](https://aws.amazon.com/kms/), to a user defined [Amazon S3](https://aws.amazon.com/s3/) bucket.

## Usage

The `vault-init` service is designed to be run alongside a Vault server and communicate over local host.

### Kubernetes

Run `vault-init` in the same Pod as the Vault container. See the [vault statefulset](statefulset.yaml) for a complete example.

## Configuration

The vault-init service supports the following environment variables for configuration:

- `S3_BUCKET_NAME` - The Amazon S3 Bucket where the vault master key and root token is stored.

- `KMS_KEY_ID` - The Amazon KMS key ID used to encrypt and decrypt the vault master key and root token.

- `VAULT_ADDR` - The vault API address.

- `CHECK_INTERVAL` ("10s") - The time duration between Vault health checks. Set
  this to a negative number to unseal once and exit.

- `VAULT_SECRET_SHARES` (5) - The number of human shares to create.

- `VAULT_SECRET_THRESHOLD` (3) - The number of human shares required to unseal.

- `VAULT_AUTO_UNSEAL` - Use Vault 1.0 native auto-unsealing directly. You must
  set the seal configuration in Vault's configuration.

- `VAULT_STORED_SHARES` (1) - Number of shares to store on KMS. Only applies to
  Vault 1.0 native auto-unseal.

- `VAULT_RECOVERY_SHARES` (1) - Number of recovery shares to generate. Only
  applies to Vault 1.0 native auto-unseal.

- `VAULT_RECOVERY_THRESHOLD` (1) - Number of recovery shares needed to unseal.
  Only applies to Vault 1.0 native auto-unseal.

- `VAULT_SKIP_VERIFY` (false) - Disable TLS validation when connecting. Setting
  to true is highly discouraged.


### Example Values

```
CHECK_INTERVAL="300"
S3_BUCKET_NAME="vault-storage"
KMS_KEY_ID="arn:aws:kms:us-east-1:1234567819:key/dead-beef-dead-beef-deadbeefdead"
VAULT_ADDR="https://vault.service.consul:8200"
```

### AWS

The `vault-init` service needs the following set of resources:

- S3 Bucket
- IAM Role + Instance Profile
- KMS Key

Here's a minimal example which creates an instance profile that can use a KMS key and read/write to a private S3 bucket.

```hcl
resource "aws_iam_role" "vault" {
  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": "sts:AssumeRole",
      "Principal": {"Service": "ec2.amazonaws.com"},
      "Effect": "Allow"
    }
  ]
}
EOF
}

# use the current caller's ARN as the KMS key administrator
data "aws_caller_identity" "current" {}

resource "aws_kms_key" "vault" {
  policy      = <<EOF
{
  "Version": "2012-10-17",
  "Id": "vault-key-policy",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {"AWS": "${data.aws_caller_identity.current.arn}"},
      "Action": "kms:*",
      "Resource": "*"
    },
    {
      "Effect": "Allow",
      "Principal": {"AWS": "${aws_iam_role.vault.arn}"},
      "Action": [
	"kms:Encrypt",
	"kms:Decrypt",
	"kms:ReEncrypt*",
	"kms:GenerateDataKey*",
	"kms:DescribeKey"
      ],
      "Resource": "*"
    }
  ]
}
EOF
}

resource "aws_kms_alias" "vault" {
  name          = "alias/my-vault-key"
  target_key_id = "${aws_kms_key.vault.key_id}"
}

resource "aws_s3_bucket" "vault" {
  acl = "private"
}

resource "aws_iam_role_policy" "vault" {
  role	 = "${aws_iam_role.vault.id}"
  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": [
	"kms:ReEncrypt*",
	"kms:GenerateDataKey*",
	"kms:Encrypt",
	"kms:DescribeKey",
	"kms:Decrypt"
      ],
      "Effect": "Allow",
      "Resource": "${aws_kms_alias.vault.arn}"
    },
    {
      "Action": "s3:ListBucket",
      "Effect": "Allow",
      "Resource": "${aws_s3_bucket.vault.arn}"
    },
    {
      "Action": ["s3:GetObject", "s3:PutObject"],
      "Effect": "Allow",
      "Resource": "${aws_s3_bucket.vault.arn}/*"
    }
  ]
}
EOF
}

resource "aws_iam_instance_profile" "vault" {
  role = "${aws_iam_role.vault.name}"
}
```

## Configuration

The vault-init service supports the following environment variables for configuration:

- `CHECK_INTERVAL` ("10s") - The time duration between Vault health checks. Set
  this to a negative number to unseal once and exit.

- `GCS_BUCKET_NAME` - The Google Cloud Storage Bucket where the vault master key
  and root token is stored.

- `KMS_KEY_ID` - The Google Cloud KMS key ID used to encrypt and decrypt the
  vault master key and root token.

- `VAULT_SECRET_SHARES` (5) - The number of human shares to create.

- `VAULT_SECRET_THRESHOLD` (3) - The number of human shares required to unseal.

- `VAULT_AUTO_UNSEAL` - Use Vault 1.0 native auto-unsealing directly. You must
  set the seal configuration in Vault's configuration.

- `VAULT_STORED_SHARES` (1) - Number of shares to store on KMS. Only applies to
  Vault 1.0 native auto-unseal.

- `VAULT_RECOVERY_SHARES` (1) - Number of recovery shares to generate. Only
  applies to Vault 1.0 native auto-unseal.

- `VAULT_RECOVERY_THRESHOLD` (1) - Number of recovery shares needed to unseal.
  Only applies to Vault 1.0 native auto-unseal.

- `VAULT_SKIP_VERIFY` (false) - Disable TLS validation when connecting. Setting
  to true is highly discouraged.

### Example Values

```
CHECK_INTERVAL="30s"
GCS_BUCKET_NAME="vault-storage"
KMS_KEY_ID="projects/my-project/locations/global/keyRings/my-keyring/cryptoKeys/key"
```


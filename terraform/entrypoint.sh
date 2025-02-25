#!/bin/sh
set -e

echo "Waiting for Vault to be ready..."
sleep 3

echo "Vault is ready - initializing Terraform"
terraform init

echo "Applying Terraform configuration..."
terraform apply -auto-approve

echo "Terraform configuration applied successfully!"

# Keep container running for debugging purposes
tail -f /dev/null
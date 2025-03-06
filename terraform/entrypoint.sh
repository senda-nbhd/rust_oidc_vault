#!/bin/sh
set -e


echo "Initializing Terraform"
terraform init

echo "Applying Terraform configuration..."
terraform apply -auto-approve

echo "Terraform configuration applied successfully!"

# Keep container running for debugging purposes
tail -f /dev/null
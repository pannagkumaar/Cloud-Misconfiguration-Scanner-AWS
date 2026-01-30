#!/bin/bash
# Export AWS Configuration for Offline Analysis
# This script exports AWS configuration to JSON for pentesting without credentials

set -e

OUTPUT_FILE="${1:-.aws-export.json}"
REGION="${2:-us-east-1}"
PROFILE="${3:-default}"

echo "🔍 Exporting AWS configuration..."
echo "   Region: $REGION"
echo "   Profile: $PROFILE"
echo "   Output: $OUTPUT_FILE"
echo ""

# Function to export service config
export_service() {
    local service=$1
    local description=$2
    
    echo "📦 Exporting $service ($description)..."
    
    case $service in
        iam)
            # Export IAM
            local iam_data='{
  "users": '$( aws iam list-users --profile $PROFILE 2>/dev/null | jq '.' || echo '{}' )',
  "roles": '$( aws iam list-roles --profile $PROFILE 2>/dev/null | jq '.' || echo '{}' )',
  "policies": '$( aws iam list-policies --scope Local --profile $PROFILE 2>/dev/null | jq '.' || echo '{}' )',
  "attached_policies": '$( aws iam list-attached-user-policies --user-name $(aws iam get-user --profile $PROFILE --query 'User.UserName' --output text 2>/dev/null || echo 'root') --profile $PROFILE 2>/dev/null | jq '.' || echo '{}' )'
}'
            echo "$iam_data"
            ;;
        s3)
            # Export S3
            local s3_data='{
  "buckets": '$( aws s3api list-buckets --profile $PROFILE 2>/dev/null | jq '.' || echo '{}' )'
}'
            echo "$s3_data"
            ;;
        ec2)
            # Export EC2
            local ec2_data='{
  "security_groups": '$( aws ec2 describe-security-groups --region $REGION --profile $PROFILE 2>/dev/null | jq '.' || echo '{}' )',
  "instances": '$( aws ec2 describe-instances --region $REGION --profile $PROFILE 2>/dev/null | jq '.' || echo '{}' )'
}'
            echo "$ec2_data"
            ;;
        rds)
            # Export RDS
            local rds_data='{
  "db_instances": '$( aws rds describe-db-instances --region $REGION --profile $PROFILE 2>/dev/null | jq '.' || echo '{}' )'
}'
            echo "$rds_data"
            ;;
    esac
}

# Build the complete export
{
    echo "{"
    echo '  "services": ["iam", "s3", "ec2", "rds"],'
    echo '  "data": {'
    
    # Export each service
    iam_export=$(export_service "iam" "Identity and Access Management" 2>/dev/null)
    s3_export=$(export_service "s3" "Simple Storage Service" 2>/dev/null)
    ec2_export=$(export_service "ec2" "Elastic Compute Cloud" 2>/dev/null)
    rds_export=$(export_service "rds" "Relational Database Service" 2>/dev/null)
    
    echo "    \"iam\": $iam_export,"
    echo "    \"s3\": $s3_export,"
    echo "    \"ec2\": $ec2_export,"
    echo "    \"rds\": $rds_export"
    echo "  }"
    echo "}"
} > "$OUTPUT_FILE"

echo ""
echo "✅ Export complete: $OUTPUT_FILE"
echo ""
echo "📊 Usage for pentesting (no credentials needed):"
echo "   python cloudscan/cmd/cloudscan.py scan --from-file $OUTPUT_FILE"

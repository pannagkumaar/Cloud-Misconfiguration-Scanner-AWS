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
        cloudtrail)
            # Export CloudTrail. describe-trails doesn't report whether a
            # trail is actively logging -- that's a separate per-trail call
            # (get-trail-status), so merge it in or CT-005 will never be
            # able to tell an active trail from a stopped one.
            local trails_json=$( aws cloudtrail describe-trails --region $REGION --profile $PROFILE 2>/dev/null | jq '.' || echo '{"trailList":[]}' )
            local merged="$trails_json"
            for name in $( echo "$trails_json" | jq -r '.trailList[]?.Name'); do
                local status=$( aws cloudtrail get-trail-status --name "$name" --region $REGION --profile $PROFILE 2>/dev/null | jq -c '{IsLogging: (.IsLogging // false)}' || echo '{"IsLogging":false}' )
                merged=$( echo "$merged" | jq --arg n "$name" --argjson s "$status" '.trailList |= map(if .Name == $n then . + $s else . end)' )
            done
            local ct_data='{
  "trails": '"$merged"'
}'
            echo "$ct_data"
            ;;
    esac
}

# Build the complete export
{
    echo "{"
    echo '  "services": ["iam", "s3", "ec2", "rds", "cloudtrail"],'
    echo '  "data": {'

    # Export each service
    iam_export=$(export_service "iam" "Identity and Access Management" 2>/dev/null)
    s3_export=$(export_service "s3" "Simple Storage Service" 2>/dev/null)
    ec2_export=$(export_service "ec2" "Elastic Compute Cloud" 2>/dev/null)
    rds_export=$(export_service "rds" "Relational Database Service" 2>/dev/null)
    cloudtrail_export=$(export_service "cloudtrail" "CloudTrail" 2>/dev/null)

    echo "    \"iam\": $iam_export,"
    echo "    \"s3\": $s3_export,"
    echo "    \"ec2\": $ec2_export,"
    echo "    \"rds\": $rds_export,"
    echo "    \"cloudtrail\": $cloudtrail_export"
    echo "  }"
    echo "}"
} > "$OUTPUT_FILE"

echo ""
echo "✅ Export complete: $OUTPUT_FILE"
echo ""
echo "📊 Usage for pentesting (no credentials needed):"
echo "   cloudscan aws-scan --from-file $OUTPUT_FILE"

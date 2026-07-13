# Export AWS Configuration for Offline Analysis
# This script exports AWS configuration to JSON for pentesting without credentials
# Usage: .\export_aws_config.ps1 -OutputFile aws-export.json -Region us-east-1 -Profile default

param(
    [string]$OutputFile = ".aws-export.json",
    [string]$Region = "us-east-1",
    [string]$Profile = "default"
)

Write-Host "🔍 Exporting AWS configuration..." -ForegroundColor Cyan
Write-Host "   Region: $Region"
Write-Host "   Profile: $Profile"
Write-Host "   Output: $OutputFile"
Write-Host ""

$data = @{
    services = @("iam", "s3", "ec2", "rds", "cloudtrail")
    data = @{}
}

# Export IAM
try {
    Write-Host "📦 Exporting IAM..." -ForegroundColor Yellow
    $data.data.iam = @{
        users = (aws iam list-users --profile $Profile | ConvertFrom-Json)
        roles = (aws iam list-roles --profile $Profile | ConvertFrom-Json)
        policies = (aws iam list-policies --scope Local --profile $Profile | ConvertFrom-Json)
    }
} catch {
    Write-Host "⚠️  IAM export failed: $_" -ForegroundColor Red
    $data.data.iam = @{}
}

# Export S3
try {
    Write-Host "📦 Exporting S3..." -ForegroundColor Yellow
    $data.data.s3 = @{
        buckets = (aws s3api list-buckets --profile $Profile | ConvertFrom-Json)
    }
} catch {
    Write-Host "⚠️  S3 export failed: $_" -ForegroundColor Red
    $data.data.s3 = @{}
}

# Export EC2
try {
    Write-Host "📦 Exporting EC2..." -ForegroundColor Yellow
    $data.data.ec2 = @{
        security_groups = (aws ec2 describe-security-groups --region $Region --profile $Profile | ConvertFrom-Json)
        instances = (aws ec2 describe-instances --region $Region --profile $Profile | ConvertFrom-Json)
    }
} catch {
    Write-Host "⚠️  EC2 export failed: $_" -ForegroundColor Red
    $data.data.ec2 = @{}
}

# Export RDS
try {
    Write-Host "📦 Exporting RDS..." -ForegroundColor Yellow
    $data.data.rds = @{
        db_instances = (aws rds describe-db-instances --region $Region --profile $Profile | ConvertFrom-Json)
    }
} catch {
    Write-Host "⚠️  RDS export failed: $_" -ForegroundColor Red
    $data.data.rds = @{}
}

# Export CloudTrail. describe-trails doesn't report whether a trail is
# actively logging -- that's a separate per-trail call (get-trail-status),
# so merge it in or CT-005 will never be able to tell an active trail from
# a stopped one.
try {
    Write-Host "📦 Exporting CloudTrail..." -ForegroundColor Yellow
    $trails = (aws cloudtrail describe-trails --region $Region --profile $Profile | ConvertFrom-Json).trailList
    foreach ($trail in $trails) {
        try {
            $status = aws cloudtrail get-trail-status --name $trail.Name --region $Region --profile $Profile | ConvertFrom-Json
            $trail | Add-Member -NotePropertyName IsLogging -NotePropertyValue ([bool]$status.IsLogging) -Force
        } catch {
            $trail | Add-Member -NotePropertyName IsLogging -NotePropertyValue $false -Force
        }
    }
    $data.data.cloudtrail = @{ trailList = $trails }
} catch {
    Write-Host "⚠️  CloudTrail export failed: $_" -ForegroundColor Red
    $data.data.cloudtrail = @{}
}

# Write output
$data | ConvertTo-Json -Depth 10 | Out-File -FilePath $OutputFile -Encoding UTF8

Write-Host ""
Write-Host "✅ Export complete: $OutputFile" -ForegroundColor Green
Write-Host ""
Write-Host "📊 Usage for pentesting (no credentials needed):" -ForegroundColor Cyan
Write-Host "   cloudscan aws-scan --from-file $OutputFile"

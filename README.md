# AWS Resource Scanner

A tool to identify unused or underutilized AWS resources and reduce cloud costs.


This script helps you find resources in your AWS environment that are potentially wasting money. It scans multiple AWS services, analyzes usage patterns, and provides actionable recommendations to optimize your cloud spending.

**Key Features:**
- Multi-service scanning (EC2, S3, RDS, Lambda, ELB)
- Smart detection of idle or underutilized resources
- Cost estimation for potential savings
- Multiple output formats (table, JSON, CSV)
- Configurable thresholds and scan parameters

## Installation

### Prerequisites
- Python 3.6+
- AWS credentials with read access to resources and CloudWatch metrics

### Setup

1. Clone this repository:
   ```bash
   git clone https://github.com/thesarfo/aws-scanner.git
   cd aws-resource-scanner
   ```

2. Create and activate a virtual environment:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## AWS Credentials Setup

The tool uses the standard AWS credentials system. You have two options:

### Option 1: AWS CLI Configuration (Recommended)
Use the AWS CLI to set up your credentials:
```bash
aws configure
```
This will prompt you for:
- AWS Access Key ID
- AWS Secret Access Key
- Default region
- Default output format

### Option 2: Environment Variables
```bash
export AWS_ACCESS_KEY_ID="your-access-key"
export AWS_SECRET_ACCESS_KEY="your-secret-key"
export AWS_DEFAULT_REGION="us-east-1"
```

## Usage

Basic usage:
```bash
python scanner.py
```

### Command-line Arguments

| Argument | Description |
|----------|-------------|
| `--profile PROFILE` | AWS profile name to use |
| `--region REGION` | AWS region to scan |
| `--days DAYS` | Number of days to consider for unused resources (default: 30) |
| `--output {table,json,csv}` | Output format (default: table) |
| `--services {ec2,s3,rds,lambda,elb,all}` | Services to scan (default: all) |

### Examples

Scan all services in a specific region:
```bash
python aws-resource-scanner.py --region us-east-1
```

Scan only EC2 and S3 resources:
```bash
python aws-resource-scanner.py --services ec2 s3
```

Use a specific AWS profile and export results as CSV:
```bash
python aws-resource-scanner.py --profile prod-account --output csv > unused-resources.csv
```

Adjust the threshold for what's considered "unused" to 60 days:
```bash
python aws-resource-scanner.py --days 60
```

## Output Formats

### Table Format (Default)

```
Potentially Unused AWS Resources:
+----------------------+------------------+------------+----------------------------------------+------------------+--------------------------------+
| Type                 | Name             | Region     | Issue                                  | Est. Monthly Cost| Recommendation                 |
+======================+==================+============+========================================+==================+================================+
| EC2 Instance         | app-server-dev   | us-east-1  | Low CPU usage (avg 2.34%)             | $70.00          | Consider stopping or downsizing|
+----------------------+------------------+------------+----------------------------------------+------------------+--------------------------------+
| RDS Instance         | postgres-dev     | us-east-1  | Low usage (CPU: 1.87%, Avg Conn: 0.3) | $60.00          | Consider stopping or downsizing|
+----------------------+------------------+------------+----------------------------------------+------------------+--------------------------------+
```

### JSON Format

```json
[
  {
    "ResourceId": "i-0123456789abcdef0",
    "ResourceType": "EC2 Instance",
    "Name": "app-server-dev",
    "Region": "us-east-1",
    "Issue": "Low CPU usage (avg 2.34%)",
    "LastActivity": "Active but idle",
    "EstimatedMonthlyCost": 70.0,
    "RecommendedAction": "Consider stopping or downsizing"
  },
  ...
]
```

### CSV Format

```
ResourceId,ResourceType,Name,Region,Issue,LastActivity,EstimatedMonthlyCost,RecommendedAction
i-0123456789abcdef0,EC2 Instance,app-server-dev,us-east-1,Low CPU usage (avg 2.34%),Active but idle,70.0,Consider stopping or downsizing
```

## What is Scanned

The tool examines the following resources for potential waste:

### EC2
- Idle instances (low CPU usage)
- Unattached EBS volumes
- Unused AMIs
- Unassociated Elastic IPs

### S3
- Empty buckets
- Buckets with low activity

### RDS
- Idle database instances (low CPU, few connections)

### Lambda
- Functions with no recent invocations

### Load Balancers
- Load balancers with little to no traffic

## Cost Estimation

The cost estimates provided by this tool are approximations based on standard AWS pricing. If you need more accurate cost information, you should verify the actual costs in your AWS billing console.

## TODOS

You can extend the scanner by:

1. Adding new service scanners
2. Adding a web interface
3. Setting up scheduled scans with reporting
4. Adding auto-cleanup capabilities (with proper safeguards)

To add a new service scanner, create a class that inherits from `ResourceScanner` and implements the `scan()` method.

## Permissions Required

This tool requires the following AWS permissions:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "ec2:Describe*",
        "s3:List*",
        "s3:GetBucket*",
        "rds:Describe*",
        "elasticloadbalancing:Describe*",
        "lambda:List*",
        "lambda:Get*",
        "cloudwatch:GetMetricStatistics"
      ],
      "Resource": "*"
    }
  ]
}
```

## Troubleshooting

### Common Issues

1. **Permission Errors**: Ensure your AWS user has the necessary permissions.
2. **No Resources Found**: Verify that you have resources in the specified region.
3. **Slow Scanning**: CloudWatch metric requests can take time. Be patient for larger accounts.
4. **NoneType Error**: In some cases, AWS API responses may be unexpected. Try scanning specific services individually.

### Logging

The tool logs information to the console. For more detailed logging, you can adjust the log level at the top of the script.


## Disclaimer

As usual, this tool is provided as-is with no warranty. Always review recommendations before deleting your AWS resources. I am absolutely not responsible for any data loss or service disruption resulting from using this tool.
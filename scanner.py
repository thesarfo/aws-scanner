#!/usr/bin/env python3
"""
AWS Resource Scanner

A tool to identify unused or underutilized AWS resources to help reduce costs.
"""

import argparse
import boto3
import datetime
import json
import logging
import sys
import time
from botocore.exceptions import ClientError
from tabulate import tabulate

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('aws-resource-scanner')

class ResourceScanner:
    """Base class for AWS resource scanners"""
    
    def __init__(self, session, days_threshold=30):
        self.session = session
        self.days_threshold = days_threshold
        self.resources = []
        
    def scan(self):
        """Scan for unused resources"""
        raise NotImplementedError("Subclasses must implement scan()")
    
    def get_resource_age(self, creation_date):
        """Calculate resource age in days"""
        if isinstance(creation_date, str):
            creation_date = datetime.datetime.fromisoformat(creation_date.replace('Z', '+00:00'))
        
        age = datetime.datetime.now(datetime.timezone.utc) - creation_date
        return age.days
    
    def get_results(self):
        """Return scan results"""
        return self.resources


class EC2Scanner(ResourceScanner):
    """Scanner for unused EC2 resources"""
    
    def scan(self):
        """Scan for unused EC2 instances, volumes, and AMIs"""
        logger.info("Scanning EC2 resources...")
        self.scan_idle_instances()
        self.scan_unattached_volumes()
        self.scan_unused_amis()
        self.scan_unused_eips()
        return self.resources
    
    def scan_idle_instances(self):
        """Scan for idle EC2 instances based on CPU utilization"""
        ec2 = self.session.resource('ec2')
        cloudwatch = self.session.client('cloudwatch')
        
        for instance in ec2.instances.all():
            if instance.state['Name'] != 'running':
                continue
                
            # Get CPU utilization for the last 14 days
            try:
                response = cloudwatch.get_metric_statistics(
                    Namespace='AWS/EC2',
                    MetricName='CPUUtilization',
                    Dimensions=[{'Name': 'InstanceId', 'Value': instance.id}],
                    StartTime=datetime.datetime.now() - datetime.timedelta(days=14),
                    EndTime=datetime.datetime.now(),
                    Period=86400,  # 1 day in seconds
                    Statistics=['Average']
                )
                
                # Check if CPU has been consistently low
                if response['Datapoints']:
                    avg_cpu = sum(point['Average'] for point in response['Datapoints']) / len(response['Datapoints'])
                    if avg_cpu < 5.0:  # Less than 5% CPU usage
                        name = self.get_resource_name(instance)
                        self.resources.append({
                            'ResourceId': instance.id,
                            'ResourceType': 'EC2 Instance',
                            'Name': name,
                            'Region': instance.placement['AvailabilityZone'][:-1],
                            'Issue': f'Low CPU usage (avg {avg_cpu:.2f}%)',
                            'LastActivity': 'Active but idle',
                            'EstimatedMonthlyCost': self.estimate_instance_cost(instance),
                            'RecommendedAction': 'Consider stopping or downsizing'
                        })
            except ClientError as e:
                logger.error(f"Error getting metrics for instance {instance.id}: {e}")
    
    def scan_unattached_volumes(self):
        """Scan for unattached EBS volumes"""
        ec2 = self.session.resource('ec2')
        
        for volume in ec2.volumes.all():
            if volume.state == 'available':  # Available means not attached
                creation_date = volume.create_time
                age_days = self.get_resource_age(creation_date)
                
                if age_days >= self.days_threshold:
                    name = self.get_resource_name(volume)
                    self.resources.append({
                        'ResourceId': volume.id,
                        'ResourceType': 'EBS Volume',
                        'Name': name,
                        'Region': volume.availability_zone[:-1],
                        'Issue': f'Unattached for {age_days} days',
                        'LastActivity': creation_date.strftime('%Y-%m-%d'),
                        'EstimatedMonthlyCost': self.estimate_volume_cost(volume),
                        'RecommendedAction': 'Delete if not needed'
                    })
    
    def scan_unused_amis(self):
        """Scan for unused AMIs (not used by any instance)"""
        ec2 = self.session.client('ec2')
        
        # Get all AMIs owned by this account
        response = ec2.describe_images(Owners=['self'])
        
        # Get all instance AMI IDs
        instances = ec2.describe_instances()
        used_amis = set()
        for reservation in instances['Reservations']:
            for instance in reservation['Instances']:
                used_amis.add(instance['ImageId'])
        
        # Find unused AMIs
        for image in response['Images']:
            if image['ImageId'] not in used_amis:
                creation_date = image.get('CreationDate')
                if creation_date:
                    age_days = self.get_resource_age(creation_date)
                    if age_days >= self.days_threshold:
                        name = image.get('Name', 'No Name')
                        self.resources.append({
                            'ResourceId': image['ImageId'],
                            'ResourceType': 'AMI',
                            'Name': name,
                            'Region': self.session.region_name,
                            'Issue': f'Unused for {age_days} days',
                            'LastActivity': creation_date,
                            'EstimatedMonthlyCost': self.estimate_ami_cost(image),
                            'RecommendedAction': 'Deregister if not needed'
                        })
    
    def scan_unused_eips(self):
        """Scan for unassociated Elastic IPs"""
        ec2 = self.session.client('ec2')
        
        response = ec2.describe_addresses()
        
        for eip in response['Addresses']:
            if 'AssociationId' not in eip:
                self.resources.append({
                    'ResourceId': eip['AllocationId'],
                    'ResourceType': 'Elastic IP',
                    'Name': 'N/A', 
                    'Region': self.session.region_name,
                    'Issue': 'Unassociated Elastic IP',
                    'LastActivity': 'Unknown',
                    'EstimatedMonthlyCost': 3.6,  # $0.005 per hour when not used = ~$3.60 per month
                    'RecommendedAction': 'Release if not needed'
                })
    
    def get_resource_name(self, resource):
        """Get the Name tag value if it exists"""
        if hasattr(resource, 'tags') and resource.tags:
            for tag in resource.tags:
                if tag['Key'] == 'Name':
                    return tag['Value']
        return 'No Name'
    
    def estimate_instance_cost(self, instance):
        """Rough estimate of instance cost - would need to be refined with real pricing API"""
        # This is a very rough estimate - in a real tool, use AWS Price List API
        instance_types = {
            't2.micro': 8.5,    # ~$0.0116 per hour
            't2.small': 17,     # ~$0.023 per hour
            't2.medium': 34,    # ~$0.0464 per hour
            'm5.large': 70,     # ~$0.096 per hour
            # Add more as needed
        }
        return instance_types.get(instance.instance_type, 50)  # Default to $50 if unknown
    
    def estimate_volume_cost(self, volume):
        """Estimate EBS volume monthly cost"""
        # Rough estimate - $0.10 per GB per month for gp2
        return round(volume.size * 0.10, 2)
    
    def estimate_ami_cost(self, image):
        """Estimate AMI cost based on snapshots"""
        # Very rough estimate - would need to calculate actual snapshot sizes
        return 5.0  # Assuming $5/month for simplicity


class S3Scanner(ResourceScanner):
    """Scanner for unused S3 resources"""
    
    def scan(self):
        """Scan for old or empty S3 buckets"""
        logger.info("Scanning S3 resources...")
        try:
            s3 = self.session.resource('s3')
            
            buckets = list(s3.buckets.all())
            logger.info(f"Found {len(buckets)} S3 buckets to scan")
            
            for bucket in buckets:
                try:
                    # Check if bucket is empty
                    objects = list(bucket.objects.limit(10))
                    if not objects:
                        self.resources.append({
                            'ResourceId': bucket.name,
                            'ResourceType': 'S3 Bucket',
                            'Name': bucket.name,
                            'Region': self.get_bucket_region(bucket.name),
                            'Issue': 'Empty bucket',
                            'LastActivity': 'N/A',
                            'EstimatedMonthlyCost': 0.0,  # Empty buckets have no storage cost
                            'RecommendedAction': 'Delete if not needed'
                        })
                        continue
                    
                    # Check for old buckets with no recent activity
                    self.check_bucket_activity(bucket)
                    
                except ClientError as e:
                    logger.error(f"Error scanning bucket {bucket.name}: {e}")
            
        except Exception as e:
            logger.error(f"Error in S3 scanner: {e}")
            
        return self.resources
    
    def get_bucket_region(self, bucket_name):
        """Get the region where a bucket is located"""
        s3 = self.session.client('s3')
        try:
            response = s3.get_bucket_location(Bucket=bucket_name)
            region = response['LocationConstraint'] or 'us-east-1'  # None means us-east-1
            return region
        except ClientError:
            return 'unknown'
    
    def check_bucket_activity(self, bucket):
        """Check bucket for recent activity using CloudWatch metrics"""
        cloudwatch = self.session.client('cloudwatch')
        
        try:
            # Check GetRequests for the last 30 days
            response = cloudwatch.get_metric_statistics(
                Namespace='AWS/S3',
                MetricName='GetRequests',
                Dimensions=[{'Name': 'BucketName', 'Value': bucket.name}],
                StartTime=datetime.datetime.now() - datetime.timedelta(days=30),
                EndTime=datetime.datetime.now(),
                Period=2592000,  # 30 days in seconds
                Statistics=['Sum']
            )
            
            # If no data or very low request count
            if not response['Datapoints'] or response['Datapoints'][0]['Sum'] < 10:
                # Calculate approximate size
                size_bytes = sum(obj.size for obj in bucket.objects.all())
                size_gb = size_bytes / (1024 ** 3)
                
                self.resources.append({
                    'ResourceId': bucket.name,
                    'ResourceType': 'S3 Bucket',
                    'Name': bucket.name,
                    'Region': self.get_bucket_region(bucket.name),
                    'Issue': 'Low activity in last 30 days',
                    'LastActivity': 'Over 30 days ago',
                    'EstimatedMonthlyCost': round(size_gb * 0.023, 2),  # $0.023 per GB for S3 Standard
                    'RecommendedAction': 'Consider migration to Glacier or deletion'
                })
        except ClientError as e:
            logger.error(f"Error checking activity for bucket {bucket.name}: {e}")


class RDSScanner(ResourceScanner):
    """Scanner for unused RDS resources"""
    
    def scan(self):
        """Scan for idle RDS instances"""
        logger.info("Scanning RDS resources...")
        rds = self.session.client('rds')
        cloudwatch = self.session.client('cloudwatch')
        
        try:
            # Get all DB instances
            response = rds.describe_db_instances()
            
            for db in response['DBInstances']:
                # Skip instances that aren't running
                if db['DBInstanceStatus'] != 'available':
                    continue
                
                # Check CPU utilization
                try:
                    cpu_response = cloudwatch.get_metric_statistics(
                        Namespace='AWS/RDS',
                        MetricName='CPUUtilization',
                        Dimensions=[{'Name': 'DBInstanceIdentifier', 'Value': db['DBInstanceIdentifier']}],
                        StartTime=datetime.datetime.now() - datetime.timedelta(days=14),
                        EndTime=datetime.datetime.now(),
                        Period=86400,  # 1 day in seconds
                        Statistics=['Average']
                    )
                    
                    # Check ConnectionCount as well
                    conn_response = cloudwatch.get_metric_statistics(
                        Namespace='AWS/RDS',
                        MetricName='DatabaseConnections',
                        Dimensions=[{'Name': 'DBInstanceIdentifier', 'Value': db['DBInstanceIdentifier']}],
                        StartTime=datetime.datetime.now() - datetime.timedelta(days=14),
                        EndTime=datetime.datetime.now(),
                        Period=86400,  # 1 day in seconds
                        Statistics=['Average']
                    )
                    
                    # Analyze metrics
                    if cpu_response['Datapoints'] and conn_response['Datapoints']:
                        avg_cpu = sum(point['Average'] for point in cpu_response['Datapoints']) / len(cpu_response['Datapoints'])
                        avg_conn = sum(point['Average'] for point in conn_response['Datapoints']) / len(conn_response['Datapoints'])
                        
                        if avg_cpu < 5.0 and avg_conn < 3.0:  # Low CPU and few connections
                            self.resources.append({
                                'ResourceId': db['DBInstanceIdentifier'],
                                'ResourceType': 'RDS Instance',
                                'Name': db['DBInstanceIdentifier'],
                                'Region': db['AvailabilityZone'][:-1],
                                'Issue': f'Low usage (CPU: {avg_cpu:.2f}%, Avg Connections: {avg_conn:.1f})',
                                'LastActivity': 'Active but idle',
                                'EstimatedMonthlyCost': self.estimate_rds_cost(db),
                                'RecommendedAction': 'Consider stopping or downsizing'
                            })
                
                except ClientError as e:
                    logger.error(f"Error getting metrics for RDS instance {db['DBInstanceIdentifier']}: {e}")
                    
        except ClientError as e:
            logger.error(f"Error scanning RDS instances: {e}")
            
        return self.resources
    
    def estimate_rds_cost(self, db_instance):
        """Estimate monthly cost for an RDS instance"""
        # Very rough estimate - would need AWS Price List API for accuracy
        instance_types = {
            'db.t3.micro': 15,
            'db.t3.small': 30,
            'db.t3.medium': 60,
            'db.m5.large': 120,
            # Add more as needed
        }
        instance_class = db_instance['DBInstanceClass']
        return instance_types.get(instance_class, 100)  # Default to $100 if unknown


class LambdaScanner(ResourceScanner):
    """Scanner for unused Lambda functions"""
    
    def scan(self):
        """Scan for unused Lambda functions"""
        logger.info("Scanning Lambda resources...")
        lambda_client = self.session.client('lambda')
        cloudwatch = self.session.client('cloudwatch')
        
        try:
            # Get all Lambda functions
            response = lambda_client.list_functions()
            
            for function in response.get('Functions', []):
                function_name = function['FunctionName']
                
                # Check invocation count
                try:
                    inv_response = cloudwatch.get_metric_statistics(
                        Namespace='AWS/Lambda',
                        MetricName='Invocations',
                        Dimensions=[{'Name': 'FunctionName', 'Value': function_name}],
                        StartTime=datetime.datetime.now() - datetime.timedelta(days=30),
                        EndTime=datetime.datetime.now(),
                        Period=2592000,  # 30 days in seconds
                        Statistics=['Sum']
                    )
                    
                    # If no invocations in the last 30 days
                    if not inv_response['Datapoints'] or inv_response['Datapoints'][0]['Sum'] == 0:
                        # Get the last update time
                        last_modified = function['LastModified']
                        last_modified_date = datetime.datetime.strptime(
                            last_modified, '%Y-%m-%dT%H:%M:%S.%f%z'
                        )
                        age_days = self.get_resource_age(last_modified_date)
                        
                        if age_days >= self.days_threshold:
                            self.resources.append({
                                'ResourceId': function_name,
                                'ResourceType': 'Lambda Function',
                                'Name': function_name,
                                'Region': self.session.region_name,
                                'Issue': f'No invocations in 30+ days, last modified {age_days} days ago',
                                'LastActivity': last_modified,
                                'EstimatedMonthlyCost': 0.0,  # Lambda is usually pay-per-use
                                'RecommendedAction': 'Delete if not needed'
                            })
                
                except ClientError as e:
                    logger.error(f"Error getting metrics for Lambda function {function_name}: {e}")
                    
        except ClientError as e:
            logger.error(f"Error scanning Lambda functions: {e}")
            
        return self.resources


class LoadBalancerScanner(ResourceScanner):
    """Scanner for unused load balancers"""
    
    def scan(self):
        """Scan for unused ELB/ALB/NLB"""
        logger.info("Scanning load balancer resources...")
        self.scan_classic_elbs()
        self.scan_application_load_balancers()
        return self.resources
    
    def scan_classic_elbs(self):
        """Scan Classic Load Balancers"""
        elb = self.session.client('elb')
        cloudwatch = self.session.client('cloudwatch')
        
        try:
            response = elb.describe_load_balancers()
            
            for lb in response.get('LoadBalancerDescriptions', []):
                lb_name = lb['LoadBalancerName']
                
                # Check request count
                try:
                    req_response = cloudwatch.get_metric_statistics(
                        Namespace='AWS/ELB',
                        MetricName='RequestCount',
                        Dimensions=[{'Name': 'LoadBalancerName', 'Value': lb_name}],
                        StartTime=datetime.datetime.now() - datetime.timedelta(days=14),
                        EndTime=datetime.datetime.now(),
                        Period=1209600,  # 14 days in seconds
                        Statistics=['Sum']
                    )
                    
                    # If no requests or very low request count
                    if not req_response['Datapoints'] or req_response['Datapoints'][0]['Sum'] < 100:
                        self.resources.append({
                            'ResourceId': lb_name,
                            'ResourceType': 'Classic ELB',
                            'Name': lb_name,
                            'Region': self.session.region_name,
                            'Issue': 'Low or no traffic in the last 14 days',
                            'LastActivity': 'Over 14 days ago',
                            'EstimatedMonthlyCost': 18.0,  # ~$18/month for Classic ELB
                            'RecommendedAction': 'Delete if not needed'
                        })
                
                except ClientError as e:
                    logger.error(f"Error getting metrics for ELB {lb_name}: {e}")
                    
        except ClientError as e:
            logger.error(f"Error scanning Classic ELBs: {e}")
    
    def scan_application_load_balancers(self):
        """Scan Application Load Balancers"""
        elbv2 = self.session.client('elbv2')
        cloudwatch = self.session.client('cloudwatch')
        
        try:
            response = elbv2.describe_load_balancers()
            
            for lb in response.get('LoadBalancers', []):
                lb_name = lb['LoadBalancerName']
                lb_arn = lb['LoadBalancerArn']
                
                # Check request count
                try:
                    req_response = cloudwatch.get_metric_statistics(
                        Namespace='AWS/ApplicationELB',
                        MetricName='RequestCount',
                        Dimensions=[{'Name': 'LoadBalancer', 'Value': lb_arn.split('/')[-1]}],
                        StartTime=datetime.datetime.now() - datetime.timedelta(days=14),
                        EndTime=datetime.datetime.now(),
                        Period=1209600,  # 14 days in seconds
                        Statistics=['Sum']
                    )
                    
                    # If no requests or very low request count
                    if not req_response['Datapoints'] or req_response['Datapoints'][0]['Sum'] < 100:
                        lb_type = 'Application Load Balancer' if lb['Type'] == 'application' else 'Network Load Balancer'
                        self.resources.append({
                            'ResourceId': lb_arn,
                            'ResourceType': lb_type,
                            'Name': lb_name,
                            'Region': self.session.region_name,
                            'Issue': 'Low or no traffic in the last 14 days',
                            'LastActivity': 'Over 14 days ago',
                            'EstimatedMonthlyCost': 22.0,  # ~$22/month for ALB/NLB
                            'RecommendedAction': 'Delete if not needed'
                        })
                
                except ClientError as e:
                    logger.error(f"Error getting metrics for ALB/NLB {lb_name}: {e}")
                    
        except ClientError as e:
            logger.error(f"Error scanning ALB/NLB: {e}")


class ResourceScannerCLI:
    """Command-line interface for the AWS Resource Scanner"""
    
    def __init__(self):
        self.parser = self.setup_arg_parser()
        self.args = self.parser.parse_args()
        self.session = None
        self.scanners = []
        self.results = []
    
    def setup_arg_parser(self):
        """Set up command-line argument parser"""
        parser = argparse.ArgumentParser(
            description='Scan AWS account for unused resources'
        )
        parser.add_argument('--profile', help='AWS profile name')
        parser.add_argument('--region', help='AWS region')
        parser.add_argument('--days', type=int, default=30,
                            help='Number of days to consider for unused resources (default: 30)')
        parser.add_argument('--output', choices=['table', 'json', 'csv'],
                            default='table', help='Output format (default: table)')
        parser.add_argument('--services', nargs='+',
                            choices=['ec2', 's3', 'rds', 'lambda', 'elb', 'all'],
                            default=['all'], help='Services to scan (default: all)')
        return parser
    
    def setup_aws_session(self):
        """Set up AWS session with provided credentials"""
        session_kwargs = {}
        
        if self.args.profile:
            session_kwargs['profile_name'] = self.args.profile
        
        self.session = boto3.Session(**session_kwargs)
        
        if self.args.region:
            self.session = boto3.Session(
                region_name=self.args.region,
                **session_kwargs
            )
    
    def setup_scanners(self):
        """Set up resource scanners based on selected services"""
        services = self.args.services
        
        if 'all' in services or 'ec2' in services:
            self.scanners.append(EC2Scanner(self.session, self.args.days))
        
        if 'all' in services or 's3' in services:
            self.scanners.append(S3Scanner(self.session, self.args.days))
        
        if 'all' in services or 'rds' in services:
            self.scanners.append(RDSScanner(self.session, self.args.days))
        
        if 'all' in services or 'lambda' in services:
            self.scanners.append(LambdaScanner(self.session, self.args.days))
        
        if 'all' in services or 'elb' in services:
            self.scanners.append(LoadBalancerScanner(self.session, self.args.days))
    
    def run_scan(self):
        """Run all configured scanners"""
        total_resources = 0
        total_cost = 0.0
        
        for scanner in self.scanners:
            resources = scanner.scan()
            self.results.extend(resources)
            total_resources += len(resources)
            total_cost += sum(r['EstimatedMonthlyCost'] for r in resources)
        
        # Sort by estimated cost (highest first)
        self.results.sort(key=lambda x: x['EstimatedMonthlyCost'], reverse=True)
        
        logger.info(f"Scan complete. Found {total_resources} potentially unused resources.")
        logger.info(f"Estimated monthly savings: ${total_cost:.2f}")
        
        return total_resources, total_cost
    
    def output_results(self, total_resources, total_cost):
        """Output results in the selected format"""
        if not self.results:
            print("No unused resources found.")
            return
        
        if self.args.output == 'json':
            print(json.dumps(self.results, indent=2, default=str))
        
        elif self.args.output == 'csv':
            # Print CSV header
            fields = ['ResourceId', 'ResourceType', 'Name', 'Region', 'Issue', 
                     'LastActivity', 'EstimatedMonthlyCost', 'RecommendedAction']
            print(','.join(fields))
            
            # Print each row
            for resource in self.results:
                print(','.join(str(resource.get(field, '')) for field in fields))
        
        else:  # table format
            # Prepare data for tabulate
            table_data = []
            for resource in self.results:
                table_data.append([
                    resource['ResourceType'],
                    resource['Name'],
                    resource['Region'],
                    resource['Issue'],
                    f"${resource['EstimatedMonthlyCost']:.2f}",
                    resource['RecommendedAction']
                ])
            
            # Print table
            print("\nPotentially Unused AWS Resources:")
            print(tabulate(
                table_data,
                headers=['Type', 'Name', 'Region', 'Issue', 'Est. Monthly Cost', 'Recommendation'],
                tablefmt='grid'
            ))
            
            print(f"\nTotal resources found: {total_resources}")
            print(f"Total estimated monthly savings: ${total_cost:.2f}")
            print(f"Total estimated annual savings: ${total_cost * 12:.2f}")
    
    def run(self):
        """Run the CLI application"""
        try:
            self.setup_aws_session()
            self.setup_scanners()
            total_resources, total_cost = self.run_scan()
            self.output_results(total_resources, total_cost)
            return 0
        except Exception as e:
            logger.error(f"Error: {e}")
            return 1


def main():
    """Main entry point"""
    cli = ResourceScannerCLI()
    sys.exit(cli.run())


if __name__ == "__main__":
    main()
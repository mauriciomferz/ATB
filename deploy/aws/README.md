# AWS Deployment Guide

Deploy ATB to Amazon EKS with IAM Roles for Service Accounts (IRSA).

## Prerequisites

- AWS CLI configured with appropriate permissions
- `eksctl` installed
- `kubectl` configured
- Helm 3.x installed

## Quick Deploy

```bash
# Set variables
CLUSTER_NAME="atb-eks"
REGION="us-east-1"
ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)

# Create EKS cluster
eksctl create cluster \
  --name $CLUSTER_NAME \
  --region $REGION \
  --version 1.28 \
  --nodegroup-name atb-nodes \
  --node-type m5.large \
  --nodes 3 \
  --nodes-min 2 \
  --nodes-max 5 \
  --with-oidc \
  --managed

# Update kubeconfig
aws eks update-kubeconfig --name $CLUSTER_NAME --region $REGION
```

## Create ECR Repository

```bash
# Create repositories
aws ecr create-repository --repository-name atb-broker --region $REGION
aws ecr create-repository --repository-name atb-agentauth --region $REGION

# Login to ECR
aws ecr get-login-password --region $REGION | docker login --username AWS --password-stdin $ACCOUNT_ID.dkr.ecr.$REGION.amazonaws.com

# Build and push
docker build -t $ACCOUNT_ID.dkr.ecr.$REGION.amazonaws.com/atb-broker:latest -f atb-gateway-go/Dockerfile.broker atb-gateway-go/
docker build -t $ACCOUNT_ID.dkr.ecr.$REGION.amazonaws.com/atb-agentauth:latest -f atb-gateway-go/Dockerfile.agentauth atb-gateway-go/

docker push $ACCOUNT_ID.dkr.ecr.$REGION.amazonaws.com/atb-broker:latest
docker push $ACCOUNT_ID.dkr.ecr.$REGION.amazonaws.com/atb-agentauth:latest
```

## Configure IRSA

```bash
# Get OIDC provider
OIDC_PROVIDER=$(aws eks describe-cluster --name $CLUSTER_NAME --region $REGION --query "cluster.identity.oidc.issuer" --output text | sed 's|https://||')

# Create IAM policy for ATB
cat > atb-policy.json << 'EOF'
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "secretsmanager:GetSecretValue",
        "kms:Decrypt"
      ],
      "Resource": "*"
    },
    {
      "Effect": "Allow",
      "Action": [
        "logs:CreateLogGroup",
        "logs:CreateLogStream",
        "logs:PutLogEvents"
      ],
      "Resource": "*"
    }
  ]
}
EOF

aws iam create-policy --policy-name ATBPolicy --policy-document file://atb-policy.json

# Create IAM role for service account
eksctl create iamserviceaccount \
  --name atb-broker \
  --namespace atb \
  --cluster $CLUSTER_NAME \
  --region $REGION \
  --attach-policy-arn arn:aws:iam::$ACCOUNT_ID:policy/ATBPolicy \
  --approve \
  --override-existing-serviceaccounts

eksctl create iamserviceaccount \
  --name atb-agentauth \
  --namespace atb \
  --cluster $CLUSTER_NAME \
  --region $REGION \
  --attach-policy-arn arn:aws:iam::$ACCOUNT_ID:policy/ATBPolicy \
  --approve \
  --override-existing-serviceaccounts
```

## Store Secrets in Secrets Manager

```bash
# Store PoA signing key
aws secretsmanager create-secret \
  --name atb/poa-signing-key \
  --secret-string file://keys/poa_ed25519.key \
  --region $REGION

# Store PoA public key
aws secretsmanager create-secret \
  --name atb/poa-public-key \
  --secret-string file://keys/poa_ed25519.pub \
  --region $REGION
```

## Deploy with Helm

```bash
# Create namespace
kubectl create namespace atb

# Install ATB
helm upgrade --install atb charts/atb \
  --namespace atb \
  --set image.registry=$ACCOUNT_ID.dkr.ecr.$REGION.amazonaws.com \
  --set broker.serviceAccount.create=false \
  --set broker.serviceAccount.name=atb-broker \
  --set agentauth.serviceAccount.create=false \
  --set agentauth.serviceAccount.name=atb-agentauth \
  --values charts/atb/values-prod.yaml
```

## Configure ALB Ingress

```bash
# Install AWS Load Balancer Controller
eksctl create iamserviceaccount \
  --cluster $CLUSTER_NAME \
  --namespace kube-system \
  --name aws-load-balancer-controller \
  --attach-policy-arn arn:aws:iam::$ACCOUNT_ID:policy/AWSLoadBalancerControllerIAMPolicy \
  --approve

helm repo add eks https://aws.github.io/eks-charts
helm install aws-load-balancer-controller eks/aws-load-balancer-controller \
  -n kube-system \
  --set clusterName=$CLUSTER_NAME \
  --set serviceAccount.create=false \
  --set serviceAccount.name=aws-load-balancer-controller

# Create ingress
cat << EOF | kubectl apply -f -
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: atb-ingress
  namespace: atb
  annotations:
    kubernetes.io/ingress.class: alb
    alb.ingress.kubernetes.io/scheme: internet-facing
    alb.ingress.kubernetes.io/target-type: ip
    alb.ingress.kubernetes.io/certificate-arn: arn:aws:acm:$REGION:$ACCOUNT_ID:certificate/YOUR-CERT-ARN
    alb.ingress.kubernetes.io/ssl-policy: ELBSecurityPolicy-TLS-1-2-2017-01
spec:
  rules:
    - host: atb.example.com
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: atb-broker
                port:
                  number: 8080
EOF
```

## Monitoring with CloudWatch

```bash
# Enable Container Insights
eksctl utils update-cluster-logging \
  --enable-types all \
  --cluster $CLUSTER_NAME \
  --region $REGION \
  --approve

# Install CloudWatch agent
kubectl apply -f https://raw.githubusercontent.com/aws-samples/amazon-cloudwatch-container-insights/latest/k8s-deployment-manifest-templates/deployment-mode/daemonset/container-insights-monitoring/quickstart/cwagent-fluentd-quickstart.yaml
```

## Verify Deployment

```bash
# Check pods
kubectl get pods -n atb

# Get ALB URL
kubectl get ingress -n atb

# Test health
curl https://atb.example.com/healthz
```

## Production Checklist

- [ ] Enable EKS audit logs
- [ ] Configure VPC endpoints for ECR/Secrets Manager
- [ ] Set up AWS WAF on ALB
- [ ] Enable GuardDuty for EKS
- [ ] Configure CloudWatch alarms
- [ ] Set up cross-region disaster recovery
- [ ] Enable encryption at rest for EBS volumes

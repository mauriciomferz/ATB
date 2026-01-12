# GCP Deployment Guide

Deploy ATB to Google Kubernetes Engine (GKE) with Workload Identity.

## Prerequisites

- `gcloud` CLI installed and authenticated
- `kubectl` configured
- Helm 3.x installed

## Quick Deploy

```bash
# Set variables
PROJECT_ID="your-project-id"
CLUSTER_NAME="atb-gke"
REGION="us-central1"
ZONE="us-central1-a"

# Set project
gcloud config set project $PROJECT_ID

# Enable APIs
gcloud services enable container.googleapis.com
gcloud services enable artifactregistry.googleapis.com
gcloud services enable secretmanager.googleapis.com

# Create GKE cluster with Workload Identity
gcloud container clusters create $CLUSTER_NAME \
  --zone $ZONE \
  --num-nodes 3 \
  --machine-type e2-standard-4 \
  --workload-pool=${PROJECT_ID}.svc.id.goog \
  --enable-network-policy \
  --enable-ip-alias \
  --release-channel regular

# Get credentials
gcloud container clusters get-credentials $CLUSTER_NAME --zone $ZONE
```

## Create Artifact Registry

```bash
# Create repository
gcloud artifacts repositories create atb-images \
  --repository-format=docker \
  --location=$REGION \
  --description="ATB container images"

# Configure Docker auth
gcloud auth configure-docker ${REGION}-docker.pkg.dev

# Build and push
docker build -t ${REGION}-docker.pkg.dev/${PROJECT_ID}/atb-images/atb-broker:latest -f atb-gateway-go/Dockerfile.broker atb-gateway-go/
docker build -t ${REGION}-docker.pkg.dev/${PROJECT_ID}/atb-images/atb-agentauth:latest -f atb-gateway-go/Dockerfile.agentauth atb-gateway-go/

docker push ${REGION}-docker.pkg.dev/${PROJECT_ID}/atb-images/atb-broker:latest
docker push ${REGION}-docker.pkg.dev/${PROJECT_ID}/atb-images/atb-agentauth:latest
```

## Configure Workload Identity

```bash
# Create GCP service account
gcloud iam service-accounts create atb-workload \
  --display-name="ATB Workload Identity"

# Grant Secret Manager access
gcloud projects add-iam-policy-binding $PROJECT_ID \
  --member="serviceAccount:atb-workload@${PROJECT_ID}.iam.gserviceaccount.com" \
  --role="roles/secretmanager.secretAccessor"

# Create Kubernetes namespace and service account
kubectl create namespace atb

kubectl create serviceaccount atb-broker -n atb
kubectl create serviceaccount atb-agentauth -n atb

# Bind Kubernetes SA to GCP SA
gcloud iam service-accounts add-iam-policy-binding \
  atb-workload@${PROJECT_ID}.iam.gserviceaccount.com \
  --role="roles/iam.workloadIdentityUser" \
  --member="serviceAccount:${PROJECT_ID}.svc.id.goog[atb/atb-broker]"

gcloud iam service-accounts add-iam-policy-binding \
  atb-workload@${PROJECT_ID}.iam.gserviceaccount.com \
  --role="roles/iam.workloadIdentityUser" \
  --member="serviceAccount:${PROJECT_ID}.svc.id.goog[atb/atb-agentauth]"

# Annotate Kubernetes service accounts
kubectl annotate serviceaccount atb-broker \
  --namespace atb \
  iam.gke.io/gcp-service-account=atb-workload@${PROJECT_ID}.iam.gserviceaccount.com

kubectl annotate serviceaccount atb-agentauth \
  --namespace atb \
  iam.gke.io/gcp-service-account=atb-workload@${PROJECT_ID}.iam.gserviceaccount.com
```

## Store Secrets in Secret Manager

```bash
# Create secrets
gcloud secrets create poa-signing-key --data-file=keys/poa_ed25519.key
gcloud secrets create poa-public-key --data-file=keys/poa_ed25519.pub

# Grant access
gcloud secrets add-iam-policy-binding poa-signing-key \
  --member="serviceAccount:atb-workload@${PROJECT_ID}.iam.gserviceaccount.com" \
  --role="roles/secretmanager.secretAccessor"

gcloud secrets add-iam-policy-binding poa-public-key \
  --member="serviceAccount:atb-workload@${PROJECT_ID}.iam.gserviceaccount.com" \
  --role="roles/secretmanager.secretAccessor"
```

## Deploy with Helm

```bash
helm upgrade --install atb charts/atb \
  --namespace atb \
  --set image.registry=${REGION}-docker.pkg.dev/${PROJECT_ID}/atb-images \
  --set broker.serviceAccount.create=false \
  --set broker.serviceAccount.name=atb-broker \
  --set agentauth.serviceAccount.create=false \
  --set agentauth.serviceAccount.name=atb-agentauth \
  --values charts/atb/values-prod.yaml
```

## Configure Cloud Load Balancing

```bash
# Reserve static IP
gcloud compute addresses create atb-ip --global

# Get IP address
gcloud compute addresses describe atb-ip --global --format="get(address)"

# Create managed certificate
cat << EOF | kubectl apply -f -
apiVersion: networking.gke.io/v1
kind: ManagedCertificate
metadata:
  name: atb-cert
  namespace: atb
spec:
  domains:
    - atb.example.com
EOF

# Create ingress
cat << EOF | kubectl apply -f -
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: atb-ingress
  namespace: atb
  annotations:
    kubernetes.io/ingress.global-static-ip-name: atb-ip
    networking.gke.io/managed-certificates: atb-cert
    kubernetes.io/ingress.class: gce
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

## Monitoring with Cloud Operations

```bash
# Enable GKE monitoring
gcloud container clusters update $CLUSTER_NAME \
  --zone $ZONE \
  --enable-managed-prometheus

# Deploy Grafana for custom dashboards
kubectl apply -f deploy/grafana/
```

## Verify Deployment

```bash
# Check pods
kubectl get pods -n atb

# Get ingress status
kubectl get ingress -n atb

# Test health (after DNS propagation)
curl https://atb.example.com/healthz
```

## Production Checklist

- [ ] Enable Binary Authorization
- [ ] Configure VPC Service Controls
- [ ] Set up Cloud Armor WAF policies
- [ ] Enable GKE audit logging
- [ ] Configure Cloud Monitoring alerts
- [ ] Set up cross-region failover
- [ ] Enable Customer-Managed Encryption Keys (CMEK)
- [ ] Configure IAP for administrative access

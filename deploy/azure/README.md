# Azure Deployment Guide

Deploy ATB to Azure Kubernetes Service (AKS) with Workload Identity.

## Prerequisites

- Azure CLI (`az`) installed and authenticated
- `kubectl` configured
- Helm 3.x installed

## Quick Deploy

```bash
# Set variables
RESOURCE_GROUP="atb-production"
CLUSTER_NAME="atb-aks"
LOCATION="eastus"
ACR_NAME="atbregistry"

# Create resource group
az group create --name $RESOURCE_GROUP --location $LOCATION

# Create AKS cluster with Workload Identity
az aks create \
  --resource-group $RESOURCE_GROUP \
  --name $CLUSTER_NAME \
  --enable-oidc-issuer \
  --enable-workload-identity \
  --node-count 3 \
  --node-vm-size Standard_D4s_v3 \
  --network-plugin azure \
  --network-policy calico \
  --generate-ssh-keys

# Get credentials
az aks get-credentials --resource-group $RESOURCE_GROUP --name $CLUSTER_NAME

# Create ACR and attach to AKS
az acr create --resource-group $RESOURCE_GROUP --name $ACR_NAME --sku Standard
az aks update --resource-group $RESOURCE_GROUP --name $CLUSTER_NAME --attach-acr $ACR_NAME
```

## Build and Push Images

```bash
# Login to ACR
az acr login --name $ACR_NAME

# Build and push
docker build -t $ACR_NAME.azurecr.io/atb-broker:latest -f atb-gateway-go/Dockerfile.broker atb-gateway-go/
docker build -t $ACR_NAME.azurecr.io/atb-agentauth:latest -f atb-gateway-go/Dockerfile.agentauth atb-gateway-go/

docker push $ACR_NAME.azurecr.io/atb-broker:latest
docker push $ACR_NAME.azurecr.io/atb-agentauth:latest
```

## Configure Workload Identity

```bash
# Get OIDC issuer URL
OIDC_ISSUER=$(az aks show --resource-group $RESOURCE_GROUP --name $CLUSTER_NAME --query "oidcIssuerProfile.issuerUrl" -o tsv)

# Create managed identity for ATB
az identity create --name atb-workload-identity --resource-group $RESOURCE_GROUP

# Get identity details
CLIENT_ID=$(az identity show --name atb-workload-identity --resource-group $RESOURCE_GROUP --query clientId -o tsv)
TENANT_ID=$(az account show --query tenantId -o tsv)

# Create federated credential
az identity federated-credential create \
  --name atb-federated-cred \
  --identity-name atb-workload-identity \
  --resource-group $RESOURCE_GROUP \
  --issuer $OIDC_ISSUER \
  --subject system:serviceaccount:atb:atb-broker \
  --audience api://AzureADTokenExchange
```

## Deploy with Helm

```bash
# Add ATB namespace
kubectl create namespace atb

# Label for workload identity
kubectl label namespace atb azure.workload.identity/use=true

# Install ATB
helm upgrade --install atb charts/atb \
  --namespace atb \
  --set image.registry=$ACR_NAME.azurecr.io \
  --set broker.serviceAccount.annotations."azure\.workload\.identity/client-id"=$CLIENT_ID \
  --set agentauth.serviceAccount.annotations."azure\.workload\.identity/client-id"=$CLIENT_ID \
  --values charts/atb/values-prod.yaml
```

## Configure Key Vault (Optional)

```bash
# Create Key Vault
az keyvault create --name atb-secrets --resource-group $RESOURCE_GROUP --location $LOCATION

# Grant access to managed identity
az keyvault set-policy --name atb-secrets \
  --secret-permissions get list \
  --object-id $(az identity show --name atb-workload-identity --resource-group $RESOURCE_GROUP --query principalId -o tsv)

# Store PoA signing key
az keyvault secret set --vault-name atb-secrets --name poa-signing-key --file keys/poa_ed25519.key
```

## Monitoring

```bash
# Enable Container Insights
az aks enable-addons --resource-group $RESOURCE_GROUP --name $CLUSTER_NAME --addons monitoring

# Deploy Prometheus/Grafana
kubectl apply -f deploy/prometheus/
kubectl apply -f deploy/grafana/
```

## Verify Deployment

```bash
# Check pods
kubectl get pods -n atb

# Check services
kubectl get svc -n atb

# Test health
kubectl port-forward svc/atb-broker 8080:8080 -n atb &
curl http://localhost:8080/healthz
```

## Production Checklist

- [ ] Enable Azure Policy for AKS
- [ ] Configure network policies
- [ ] Set up Azure AD integration
- [ ] Enable Defender for Containers
- [ ] Configure backup for Key Vault
- [ ] Set up Azure Monitor alerts
- [ ] Enable audit logging

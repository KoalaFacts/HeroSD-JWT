# HeroSD-JWT Deployment Guide

**Step-by-Step Deployment Instructions for Production Environments**

This guide walks you through deploying HeroSD-JWT in various environments with production-ready configurations.

---

## Table of Contents

- [Prerequisites](#prerequisites)
- [Docker Deployment](#docker-deployment)
- [Kubernetes Deployment](#kubernetes-deployment)
- [Azure Deployment](#azure-deployment)
- [AWS Deployment](#aws-deployment)
- [IIS Deployment](#iis-deployment)
- [CI/CD Integration](#cicd-integration)
- [Post-Deployment Verification](#post-deployment-verification)

---

## Prerequisites

### Development Machine Setup

```bash
# Install .NET 8.0 SDK or higher
# Windows (using winget)
winget install Microsoft.DotNet.SDK.8

# macOS (using Homebrew)
brew install dotnet

# Linux (Ubuntu)
wget https://dot.net/v1/dotnet-install.sh
chmod +x dotnet-install.sh
./dotnet-install.sh --channel 8.0

# Verify installation
dotnet --version  # Should be 8.0.x or higher
```

### Install HeroSD-JWT NuGet Packages

```bash
# Core library
dotnet add package HeroSdJwt

# ASP.NET Core integration (if building web API)
dotnet add package HeroSdJwt.AspNetCore

# Verify packages
dotnet list package
```

### Sample Application Setup

Create a minimal API to test deployment:

```csharp
// Program.cs
using HeroSdJwt.AspNetCore;

var builder = WebApplication.CreateBuilder(args);

// Add services
builder.Services.AddSdJwtAuthentication(options =>
{
    options.Issuer = builder.Configuration["SdJwt:Issuer"];
    options.Audience = builder.Configuration["SdJwt:Audience"];
    options.KeyResolver = async (kid, ct) =>
    {
        // Implement key resolution (see examples below)
        return await GetPublicKeyAsync(kid, ct);
    };
});

builder.Services.AddAuthorization();

var app = builder.Build();

// Configure middleware
app.UseAuthentication();
app.UseAuthorization();

// Health check endpoint
app.MapGet("/health", () => Results.Ok(new { status = "healthy", timestamp = DateTime.UtcNow }));

// Protected endpoint
app.MapGet("/protected", () => Results.Ok(new { message = "Hello from protected endpoint!" }))
   .RequireAuthorization();

app.Run();
```

### Configuration File

```json
// appsettings.json
{
  "SdJwt": {
    "Issuer": "https://issuer.example.com",
    "Audience": "api://my-api",
    "ClockSkew": "00:02:00",
    "RequireKeyBinding": true
  },
  "Logging": {
    "LogLevel": {
      "Default": "Information",
      "HeroSdJwt": "Information",
      "Microsoft.AspNetCore": "Warning"
    }
  },
  "AllowedHosts": "*"
}
```

---

## Docker Deployment

### Dockerfile

```dockerfile
# Use official .NET 8.0 runtime as base
FROM mcr.microsoft.com/dotnet/aspnet:8.0 AS base
WORKDIR /app
EXPOSE 8080
EXPOSE 8081

# Build stage
FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
ARG BUILD_CONFIGURATION=Release
WORKDIR /src

# Copy project files
COPY ["MyApi/MyApi.csproj", "MyApi/"]
RUN dotnet restore "MyApi/MyApi.csproj"

# Copy source code and build
COPY . .
WORKDIR "/src/MyApi"
RUN dotnet build "MyApi.csproj" -c $BUILD_CONFIGURATION -o /app/build

# Publish stage
FROM build AS publish
ARG BUILD_CONFIGURATION=Release
RUN dotnet publish "MyApi.csproj" \
    -c $BUILD_CONFIGURATION \
    -o /app/publish \
    /p:UseAppHost=false

# Final stage
FROM base AS final
WORKDIR /app
COPY --from=publish /app/publish .

# Create non-root user
RUN adduser --disabled-password --gecos "" appuser && chown -R appuser /app
USER appuser

ENTRYPOINT ["dotnet", "MyApi.dll"]
```

### docker-compose.yml

```yaml
version: '3.8'

services:
  sdjwt-api:
    build:
      context: .
      dockerfile: Dockerfile
    image: sdjwt-api:latest
    container_name: sdjwt-api
    ports:
      - "8080:8080"
    environment:
      - ASPNETCORE_ENVIRONMENT=Production
      - ASPNETCORE_URLS=http://+:8080
      - SdJwt__Issuer=https://issuer.example.com
      - SdJwt__Audience=api://my-api
    volumes:
      - ./config:/app/config:ro
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8080/health"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 40s
    networks:
      - sdjwt-network

  # Optional: Redis for distributed caching
  redis:
    image: redis:7-alpine
    container_name: sdjwt-redis
    ports:
      - "6379:6379"
    volumes:
      - redis-data:/data
    networks:
      - sdjwt-network

  # Optional: Prometheus for metrics
  prometheus:
    image: prom/prometheus:latest
    container_name: sdjwt-prometheus
    ports:
      - "9090:9090"
    volumes:
      - ./prometheus.yml:/etc/prometheus/prometheus.yml:ro
      - prometheus-data:/prometheus
    command:
      - '--config.file=/etc/prometheus/prometheus.yml'
      - '--storage.tsdb.path=/prometheus'
    networks:
      - sdjwt-network

networks:
  sdjwt-network:
    driver: bridge

volumes:
  redis-data:
  prometheus-data:
```

### Build and Run

```bash
# Build the image
docker build -t sdjwt-api:v1.0.0 .

# Run standalone container
docker run -d \
  --name sdjwt-api \
  -p 8080:8080 \
  -e ASPNETCORE_ENVIRONMENT=Production \
  -e SdJwt__Issuer=https://issuer.example.com \
  sdjwt-api:v1.0.0

# Or use docker-compose
docker-compose up -d

# Check logs
docker logs -f sdjwt-api

# Test health endpoint
curl http://localhost:8080/health
```

### Push to Container Registry

```bash
# Docker Hub
docker tag sdjwt-api:v1.0.0 myregistry/sdjwt-api:v1.0.0
docker push myregistry/sdjwt-api:v1.0.0

# Azure Container Registry
az acr login --name myregistry
docker tag sdjwt-api:v1.0.0 myregistry.azurecr.io/sdjwt-api:v1.0.0
docker push myregistry.azurecr.io/sdjwt-api:v1.0.0

# AWS ECR
aws ecr get-login-password --region us-east-1 | docker login --username AWS --password-stdin 123456789012.dkr.ecr.us-east-1.amazonaws.com
docker tag sdjwt-api:v1.0.0 123456789012.dkr.ecr.us-east-1.amazonaws.com/sdjwt-api:v1.0.0
docker push 123456789012.dkr.ecr.us-east-1.amazonaws.com/sdjwt-api:v1.0.0
```

---

## Kubernetes Deployment

### Namespace

```yaml
# namespace.yaml
apiVersion: v1
kind: Namespace
metadata:
  name: sdjwt-system
  labels:
    name: sdjwt-system
```

### ConfigMap

```yaml
# configmap.yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: sdjwt-config
  namespace: sdjwt-system
data:
  appsettings.Production.json: |
    {
      "SdJwt": {
        "Issuer": "https://issuer.production.com",
        "Audience": "api://production-api",
        "ClockSkew": "00:02:00",
        "RequireKeyBinding": true,
        "TokenScheme": "Bearer"
      },
      "Logging": {
        "LogLevel": {
          "Default": "Information",
          "HeroSdJwt": "Information"
        }
      }
    }
```

### Secret

```yaml
# secret.yaml
apiVersion: v1
kind: Secret
metadata:
  name: sdjwt-secrets
  namespace: sdjwt-system
type: Opaque
data:
  # Base64 encoded values
  fallback-key: <base64-encoded-jwk>
```

**Generate secret:**
```bash
# Create secret from file
kubectl create secret generic sdjwt-secrets \
  --from-file=fallback-key=./keys/fallback-key.json \
  --namespace=sdjwt-system

# Or from literal
kubectl create secret generic sdjwt-secrets \
  --from-literal=fallback-key='{"kty":"RSA",...}' \
  --namespace=sdjwt-system
```

### Deployment

```yaml
# deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: sdjwt-api
  namespace: sdjwt-system
  labels:
    app: sdjwt-api
    version: v1.0.0
spec:
  replicas: 3
  strategy:
    type: RollingUpdate
    rollingUpdate:
      maxSurge: 1
      maxUnavailable: 0
  selector:
    matchLabels:
      app: sdjwt-api
  template:
    metadata:
      labels:
        app: sdjwt-api
        version: v1.0.0
      annotations:
        prometheus.io/scrape: "true"
        prometheus.io/port: "8080"
        prometheus.io/path: "/metrics"
    spec:
      serviceAccountName: sdjwt-sa
      securityContext:
        runAsNonRoot: true
        runAsUser: 1000
        fsGroup: 1000
      containers:
      - name: api
        image: myregistry.azurecr.io/sdjwt-api:v1.0.0
        imagePullPolicy: Always
        ports:
        - name: http
          containerPort: 8080
          protocol: TCP
        env:
        - name: ASPNETCORE_ENVIRONMENT
          value: "Production"
        - name: ASPNETCORE_URLS
          value: "http://+:8080"
        - name: SdJwt__Issuer
          valueFrom:
            configMapKeyRef:
              name: sdjwt-config
              key: issuer
        - name: SdJwt__FallbackKey
          valueFrom:
            secretKeyRef:
              name: sdjwt-secrets
              key: fallback-key
        volumeMounts:
        - name: config
          mountPath: /app/config
          readOnly: true
        resources:
          requests:
            memory: "256Mi"
            cpu: "250m"
          limits:
            memory: "512Mi"
            cpu: "500m"
        livenessProbe:
          httpGet:
            path: /health/live
            port: http
          initialDelaySeconds: 30
          periodSeconds: 10
          timeoutSeconds: 5
          failureThreshold: 3
        readinessProbe:
          httpGet:
            path: /health/ready
            port: http
          initialDelaySeconds: 5
          periodSeconds: 5
          timeoutSeconds: 3
          successThreshold: 1
          failureThreshold: 3
        startupProbe:
          httpGet:
            path: /health/startup
            port: http
          initialDelaySeconds: 0
          periodSeconds: 10
          timeoutSeconds: 3
          successThreshold: 1
          failureThreshold: 30
      volumes:
      - name: config
        configMap:
          name: sdjwt-config
      affinity:
        podAntiAffinity:
          preferredDuringSchedulingIgnoredDuringExecution:
          - weight: 100
            podAffinityTerm:
              labelSelector:
                matchExpressions:
                - key: app
                  operator: In
                  values:
                  - sdjwt-api
              topologyKey: kubernetes.io/hostname
---
# Service
apiVersion: v1
kind: Service
metadata:
  name: sdjwt-api
  namespace: sdjwt-system
  labels:
    app: sdjwt-api
spec:
  type: ClusterIP
  ports:
  - port: 80
    targetPort: http
    protocol: TCP
    name: http
  selector:
    app: sdjwt-api
---
# Service Account
apiVersion: v1
kind: ServiceAccount
metadata:
  name: sdjwt-sa
  namespace: sdjwt-system
---
# Horizontal Pod Autoscaler
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: sdjwt-api-hpa
  namespace: sdjwt-system
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: sdjwt-api
  minReplicas: 3
  maxReplicas: 10
  metrics:
  - type: Resource
    resource:
      name: cpu
      target:
        type: Utilization
        averageUtilization: 70
  - type: Resource
    resource:
      name: memory
      target:
        type: Utilization
        averageUtilization: 80
  behavior:
    scaleDown:
      stabilizationWindowSeconds: 300
      policies:
      - type: Percent
        value: 50
        periodSeconds: 60
    scaleUp:
      stabilizationWindowSeconds: 0
      policies:
      - type: Percent
        value: 100
        periodSeconds: 15
      - type: Pods
        value: 2
        periodSeconds: 15
      selectPolicy: Max
```

### Ingress

```yaml
# ingress.yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: sdjwt-api-ingress
  namespace: sdjwt-system
  annotations:
    cert-manager.io/cluster-issuer: letsencrypt-prod
    nginx.ingress.kubernetes.io/rate-limit: "100"
    nginx.ingress.kubernetes.io/ssl-redirect: "true"
spec:
  ingressClassName: nginx
  tls:
  - hosts:
    - api.example.com
    secretName: sdjwt-tls
  rules:
  - host: api.example.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: sdjwt-api
            port:
              number: 80
```

### Deploy to Kubernetes

```bash
# Create namespace
kubectl apply -f namespace.yaml

# Create secrets and configs
kubectl apply -f secret.yaml
kubectl apply -f configmap.yaml

# Deploy application
kubectl apply -f deployment.yaml

# Create ingress
kubectl apply -f ingress.yaml

# Verify deployment
kubectl get all -n sdjwt-system

# Check pod status
kubectl get pods -n sdjwt-system -w

# Check logs
kubectl logs -f deployment/sdjwt-api -n sdjwt-system

# Test service
kubectl port-forward -n sdjwt-system svc/sdjwt-api 8080:80
curl http://localhost:8080/health
```

---

## Azure Deployment

### Azure App Service

#### Using Azure CLI

```bash
# Login to Azure
az login

# Create resource group
az group create \
  --name sdjwt-rg \
  --location eastus

# Create App Service plan
az appservice plan create \
  --name sdjwt-plan \
  --resource-group sdjwt-rg \
  --sku P1V2 \
  --is-linux

# Create web app
az webapp create \
  --name sdjwt-api-prod \
  --resource-group sdjwt-rg \
  --plan sdjwt-plan \
  --runtime "DOTNETCORE:8.0"

# Configure app settings
az webapp config appsettings set \
  --name sdjwt-api-prod \
  --resource-group sdjwt-rg \
  --settings \
    ASPNETCORE_ENVIRONMENT=Production \
    SdJwt__Issuer=https://issuer.example.com \
    SdJwt__Audience=api://my-api \
    SdJwt__ClockSkew=00:02:00

# Deploy from container registry
az webapp config container set \
  --name sdjwt-api-prod \
  --resource-group sdjwt-rg \
  --docker-custom-image-name myregistry.azurecr.io/sdjwt-api:v1.0.0 \
  --docker-registry-server-url https://myregistry.azurecr.io

# Configure health check
az webapp config set \
  --name sdjwt-api-prod \
  --resource-group sdjwt-rg \
  --health-check-path "/health"

# Scale out
az appservice plan update \
  --name sdjwt-plan \
  --resource-group sdjwt-rg \
  --number-of-workers 3
```

### Azure Key Vault Integration

```bash
# Create Key Vault
az keyvault create \
  --name sdjwt-keyvault \
  --resource-group sdjwt-rg \
  --location eastus

# Enable managed identity for App Service
az webapp identity assign \
  --name sdjwt-api-prod \
  --resource-group sdjwt-rg

# Get the managed identity principal ID
PRINCIPAL_ID=$(az webapp identity show \
  --name sdjwt-api-prod \
  --resource-group sdjwt-rg \
  --query principalId -o tsv)

# Grant Key Vault access to managed identity
az keyvault set-policy \
  --name sdjwt-keyvault \
  --object-id $PRINCIPAL_ID \
  --key-permissions get list \
  --secret-permissions get list

# Add signing key to Key Vault
az keyvault key create \
  --vault-name sdjwt-keyvault \
  --name signing-key-v1 \
  --kty EC \
  --curve P-256 \
  --protection software

# Configure app to use Key Vault
az webapp config appsettings set \
  --name sdjwt-api-prod \
  --resource-group sdjwt-rg \
  --settings \
    KeyVault__Endpoint=https://sdjwt-keyvault.vault.azure.net/
```

### Application Code for Azure Key Vault

```csharp
// Program.cs
using Azure.Identity;
using Azure.Security.KeyVault.Keys;
using Azure.Security.KeyVault.Keys.Cryptography;

var builder = WebApplication.CreateBuilder(args);

// Add Azure Key Vault
if (builder.Environment.IsProduction())
{
    var keyVaultEndpoint = new Uri(builder.Configuration["KeyVault:Endpoint"]!);

    builder.Services.AddSdJwtAuthentication(options =>
    {
        options.KeyResolver = async (kid, cancellationToken) =>
        {
            var keyClient = new KeyClient(keyVaultEndpoint, new DefaultAzureCredential());
            var key = await keyClient.GetKeyAsync(kid, cancellationToken: cancellationToken);

            // Convert Azure Key Vault key to JsonWebKey
            return new JsonWebKey
            {
                Kty = key.Value.KeyType.ToString(),
                Kid = key.Value.Name,
                X = key.Value.Key.X != null ? Base64UrlEncoder.Encode(key.Value.Key.X) : null,
                Y = key.Value.Key.Y != null ? Base64UrlEncoder.Encode(key.Value.Key.Y) : null,
                Crv = key.Value.Key.CurveName?.ToString()
            };
        };
    });
}
```

### Azure Container Instances (ACI)

```bash
# Deploy to ACI
az container create \
  --resource-group sdjwt-rg \
  --name sdjwt-api-aci \
  --image myregistry.azurecr.io/sdjwt-api:v1.0.0 \
  --registry-login-server myregistry.azurecr.io \
  --registry-username <username> \
  --registry-password <password> \
  --dns-name-label sdjwt-api \
  --ports 80 443 \
  --cpu 2 \
  --memory 4 \
  --environment-variables \
    ASPNETCORE_ENVIRONMENT=Production \
    SdJwt__Issuer=https://issuer.example.com \
  --secure-environment-variables \
    SdJwt__FallbackKey='{"kty":"RSA",...}'
```

---

## AWS Deployment

### AWS Elastic Beanstalk

```bash
# Install EB CLI
pip install awsebcli

# Initialize EB application
eb init -p "64bit Amazon Linux 2 v2.5.0 running .NET Core" sdjwt-api

# Create environment
eb create sdjwt-prod-env \
  --instance-type t3.medium \
  --min-instances 2 \
  --max-instances 10 \
  --envvars \
    ASPNETCORE_ENVIRONMENT=Production,\
    SdJwt__Issuer=https://issuer.example.com

# Deploy
eb deploy

# Check status
eb status

# View logs
eb logs
```

### AWS ECS (Elastic Container Service)

```bash
# Create ECS cluster
aws ecs create-cluster --cluster-name sdjwt-cluster

# Register task definition
cat > task-definition.json <<EOF
{
  "family": "sdjwt-api",
  "networkMode": "awsvpc",
  "requiresCompatibilities": ["FARGATE"],
  "cpu": "512",
  "memory": "1024",
  "containerDefinitions": [
    {
      "name": "sdjwt-api",
      "image": "123456789012.dkr.ecr.us-east-1.amazonaws.com/sdjwt-api:v1.0.0",
      "portMappings": [
        {
          "containerPort": 8080,
          "protocol": "tcp"
        }
      ],
      "environment": [
        {
          "name": "ASPNETCORE_ENVIRONMENT",
          "value": "Production"
        },
        {
          "name": "SdJwt__Issuer",
          "value": "https://issuer.example.com"
        }
      ],
      "secrets": [
        {
          "name": "SdJwt__FallbackKey",
          "valueFrom": "arn:aws:secretsmanager:us-east-1:123456789012:secret:sdjwt-fallback-key"
        }
      ],
      "healthCheck": {
        "command": ["CMD-SHELL", "curl -f http://localhost:8080/health || exit 1"],
        "interval": 30,
        "timeout": 5,
        "retries": 3,
        "startPeriod": 60
      },
      "logConfiguration": {
        "logDriver": "awslogs",
        "options": {
          "awslogs-group": "/ecs/sdjwt-api",
          "awslogs-region": "us-east-1",
          "awslogs-stream-prefix": "ecs"
        }
      }
    }
  ]
}
EOF

aws ecs register-task-definition --cli-input-json file://task-definition.json

# Create service
aws ecs create-service \
  --cluster sdjwt-cluster \
  --service-name sdjwt-api-service \
  --task-definition sdjwt-api \
  --desired-count 3 \
  --launch-type FARGATE \
  --network-configuration "awsvpcConfiguration={subnets=[subnet-12345],securityGroups=[sg-12345],assignPublicIp=ENABLED}"
```

### AWS Secrets Manager Integration

```csharp
// Add NuGet package: AWSSDK.SecretsManager
using Amazon.SecretsManager;
using Amazon.SecretsManager.Model;

var builder = WebApplication.CreateBuilder(args);

if (builder.Environment.IsProduction())
{
    var secretsManager = new AmazonSecretsManagerClient();

    builder.Services.AddSdJwtAuthentication(options =>
    {
        options.KeyResolver = async (kid, ct) =>
        {
            var request = new GetSecretValueRequest
            {
                SecretId = $"sdjwt-keys/{kid}"
            };

            var response = await secretsManager.GetSecretValueAsync(request, ct);
            var keyJson = response.SecretString;

            return JsonSerializer.Deserialize<JsonWebKey>(keyJson);
        };
    });
}
```

---

## IIS Deployment

### Prerequisites

```powershell
# Install .NET 8.0 Hosting Bundle
# Download from: https://dotnet.microsoft.com/download/dotnet/8.0
# Install: dotnet-hosting-8.0.x-win.exe

# Verify installation
dotnet --info

# Enable IIS features
Enable-WindowsOptionalFeature -Online -FeatureName IIS-WebServerRole
Enable-WindowsOptionalFeature -Online -FeatureName IIS-WebServer
Enable-WindowsOptionalFeature -Online -FeatureName IIS-ASPNET45
```

### Publish Application

```bash
# Publish for IIS deployment
dotnet publish -c Release -o ./publish

# Or with self-contained deployment
dotnet publish -c Release -r win-x64 --self-contained true -o ./publish
```

### web.config

```xml
<?xml version="1.0" encoding="utf-8"?>
<configuration>
  <location path="." inheritInChildApplications="false">
    <system.webServer>
      <handlers>
        <add name="aspNetCore" path="*" verb="*" modules="AspNetCoreModuleV2" resourceType="Unspecified" />
      </handlers>
      <aspNetCore processPath="dotnet"
                  arguments=".\MyApi.dll"
                  stdoutLogEnabled="true"
                  stdoutLogFile=".\logs\stdout"
                  hostingModel="inprocess">
        <environmentVariables>
          <environmentVariable name="ASPNETCORE_ENVIRONMENT" value="Production" />
          <environmentVariable name="SdJwt__Issuer" value="https://issuer.example.com" />
        </environmentVariables>
      </aspNetCore>
    </system.webServer>
  </location>
</configuration>
```

### Create IIS Site

```powershell
# Import IIS module
Import-Module WebAdministration

# Create application pool
New-WebAppPool -Name "SdJwtApiPool"
Set-ItemProperty IIS:\AppPools\SdJwtApiPool -Name "managedRuntimeVersion" -Value ""

# Create website
New-Website -Name "SdJwtApi" `
  -Port 80 `
  -PhysicalPath "C:\inetpub\sdjwt-api" `
  -ApplicationPool "SdJwtApiPool"

# Copy published files
Copy-Item -Path ".\publish\*" -Destination "C:\inetpub\sdjwt-api" -Recurse

# Start website
Start-Website -Name "SdJwtApi"

# Test
Invoke-WebRequest -Uri "http://localhost/health"
```

---

## CI/CD Integration

### GitHub Actions

```yaml
# .github/workflows/deploy.yml
name: Deploy to Production

on:
  push:
    branches: [main]
  workflow_dispatch:

env:
  DOTNET_VERSION: '8.0.x'
  REGISTRY: ghcr.io
  IMAGE_NAME: ${{ github.repository }}

jobs:
  build-and-test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Setup .NET
        uses: actions/setup-dotnet@v4
        with:
          dotnet-version: ${{ env.DOTNET_VERSION }}

      - name: Restore dependencies
        run: dotnet restore

      - name: Build
        run: dotnet build --no-restore -c Release

      - name: Test
        run: dotnet test --no-build -c Release --verbosity normal

      - name: Publish
        run: dotnet publish -c Release -o ./publish

      - name: Upload artifact
        uses: actions/upload-artifact@v4
        with:
          name: published-app
          path: ./publish

  build-docker:
    needs: build-and-test
    runs-on: ubuntu-latest
    permissions:
      contents: read
      packages: write
    steps:
      - uses: actions/checkout@v4

      - name: Log in to Container Registry
        uses: docker/login-action@v3
        with:
          registry: ${{ env.REGISTRY }}
          username: ${{ github.actor }}
          password: ${{ secrets.GITHUB_TOKEN }}

      - name: Extract metadata
        id: meta
        uses: docker/metadata-action@v5
        with:
          images: ${{ env.REGISTRY }}/${{ env.IMAGE_NAME }}
          tags: |
            type=ref,event=branch
            type=ref,event=pr
            type=semver,pattern={{version}}
            type=sha

      - name: Build and push Docker image
        uses: docker/build-push-action@v5
        with:
          context: .
          push: true
          tags: ${{ steps.meta.outputs.tags }}
          labels: ${{ steps.meta.outputs.labels }}

  deploy-kubernetes:
    needs: build-docker
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Set up kubectl
        uses: azure/setup-kubectl@v3

      - name: Configure kubectl
        run: |
          echo "${{ secrets.KUBECONFIG }}" | base64 -d > kubeconfig
          export KUBECONFIG=./kubeconfig

      - name: Deploy to Kubernetes
        run: |
          kubectl set image deployment/sdjwt-api \
            api=${{ env.REGISTRY }}/${{ env.IMAGE_NAME }}:sha-${{ github.sha }} \
            -n sdjwt-system

          kubectl rollout status deployment/sdjwt-api -n sdjwt-system

      - name: Verify deployment
        run: |
          kubectl get pods -n sdjwt-system
          kubectl logs -l app=sdjwt-api -n sdjwt-system --tail=50
```

### Azure DevOps Pipeline

```yaml
# azure-pipelines.yml
trigger:
  branches:
    include:
      - main

pool:
  vmImage: 'ubuntu-latest'

variables:
  buildConfiguration: 'Release'
  dotnetVersion: '8.0.x'

stages:
  - stage: Build
    jobs:
      - job: BuildAndTest
        steps:
          - task: UseDotNet@2
            inputs:
              version: $(dotnetVersion)

          - task: DotNetCoreCLI@2
            displayName: 'Restore dependencies'
            inputs:
              command: 'restore'

          - task: DotNetCoreCLI@2
            displayName: 'Build'
            inputs:
              command: 'build'
              arguments: '--configuration $(buildConfiguration)'

          - task: DotNetCoreCLI@2
            displayName: 'Run tests'
            inputs:
              command: 'test'
              arguments: '--configuration $(buildConfiguration) --collect:"XPlat Code Coverage"'

          - task: DotNetCoreCLI@2
            displayName: 'Publish'
            inputs:
              command: 'publish'
              publishWebProjects: true
              arguments: '--configuration $(buildConfiguration) --output $(Build.ArtifactStagingDirectory)'

          - task: PublishBuildArtifacts@1
            inputs:
              pathToPublish: '$(Build.ArtifactStagingDirectory)'
              artifactName: 'drop'

  - stage: Deploy
    dependsOn: Build
    condition: succeeded()
    jobs:
      - deployment: DeployToProduction
        environment: 'production'
        strategy:
          runOnce:
            deploy:
              steps:
                - task: AzureWebApp@1
                  inputs:
                    azureSubscription: 'Azure-Subscription'
                    appType: 'webAppLinux'
                    appName: 'sdjwt-api-prod'
                    package: '$(Pipeline.Workspace)/drop/**/*.zip'
```

---

## Post-Deployment Verification

### Verification Checklist

```bash
#!/bin/bash
# verify-deployment.sh

API_URL="https://api.example.com"
SUCCESS=0
FAILED=0

echo "=== Post-Deployment Verification ==="

# Test 1: Health check
echo "[1/6] Testing health endpoint..."
if curl -sf "$API_URL/health" > /dev/null; then
    echo "✓ Health check passed"
    ((SUCCESS++))
else
    echo "✗ Health check failed"
    ((FAILED++))
fi

# Test 2: Metrics endpoint
echo "[2/6] Testing metrics endpoint..."
if curl -sf "$API_URL/metrics" | grep -q "sdjwt_verification_count"; then
    echo "✓ Metrics available"
    ((SUCCESS++))
else
    echo "✗ Metrics not available"
    ((FAILED++))
fi

# Test 3: Authentication (should return 401 without token)
echo "[3/6] Testing authentication..."
STATUS=$(curl -s -o /dev/null -w "%{http_code}" "$API_URL/protected")
if [ "$STATUS" -eq 401 ]; then
    echo "✓ Authentication configured correctly"
    ((SUCCESS++))
else
    echo "✗ Authentication not working (got $STATUS)"
    ((FAILED++))
fi

# Test 4: Valid token authentication
echo "[4/6] Testing with valid token..."
TOKEN="<valid-test-token>"
STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
  -H "Authorization: Bearer $TOKEN" \
  "$API_URL/protected")
if [ "$STATUS" -eq 200 ]; then
    echo "✓ Token authentication working"
    ((SUCCESS++))
else
    echo "✗ Token authentication failed (got $STATUS)"
    ((FAILED++))
fi

# Test 5: TLS/SSL
echo "[5/6] Testing TLS..."
if curl -sf "$API_URL" > /dev/null 2>&1; then
    echo "✓ TLS configured correctly"
    ((SUCCESS++))
else
    echo "✗ TLS issue detected"
    ((FAILED++))
fi

# Test 6: Response time
echo "[6/6] Testing response time..."
RESPONSE_TIME=$(curl -s -o /dev/null -w "%{time_total}" "$API_URL/health")
if (( $(echo "$RESPONSE_TIME < 1.0" | bc -l) )); then
    echo "✓ Response time acceptable (${RESPONSE_TIME}s)"
    ((SUCCESS++))
else
    echo "⚠ Response time slow (${RESPONSE_TIME}s)"
    ((FAILED++))
fi

# Summary
echo ""
echo "=== Verification Summary ==="
echo "Passed: $SUCCESS/6"
echo "Failed: $FAILED/6"

if [ $FAILED -eq 0 ]; then
    echo "✓ Deployment verification PASSED"
    exit 0
else
    echo "✗ Deployment verification FAILED"
    exit 1
fi
```

### Monitor Deployment

```bash
# Watch pod rollout
kubectl rollout status deployment/sdjwt-api -n sdjwt-system -w

# Watch logs during deployment
kubectl logs -f deployment/sdjwt-api -n sdjwt-system

# Check for errors
kubectl logs deployment/sdjwt-api -n sdjwt-system | grep -i error

# Check metrics
curl https://api.example.com/metrics | grep sdjwt
```

---

## Summary

Congratulations! You've successfully deployed HeroSD-JWT to production.

**Next steps:**
1. Set up monitoring dashboards (see [operations.md](operations.md))
2. Configure alerts for critical metrics
3. Review [troubleshooting.md](troubleshooting.md) for common issues
4. Implement your key rotation schedule
5. Document your deployment-specific configurations

For questions or issues:
- GitHub Issues: https://github.com/KoalaFacts/HeroSD-JWT/issues
- Discussions: https://github.com/KoalaFacts/HeroSD-JWT/discussions

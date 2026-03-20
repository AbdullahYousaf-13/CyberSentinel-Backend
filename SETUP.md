# CyberSentinel Cloud Deployment (AWS ECS Fargate)

This guide is for deploying `CyberSentinel-Backend` to AWS and using your ML models safely.

## 0) What was fixed in code

Already handled in this repo:

1. Added model import script: `scripts/bootstrap_models.py`
2. Added strict feature-shape validation in inference engine
3. Backend now fails fast with clear errors if model features do not match extractor features

## 1) Prerequisites (you must do)

1. Install AWS CLI v2
2. Install Docker Desktop
3. Have an AWS account with permissions for ECR, ECS, IAM, CloudWatch, EC2 networking
4. Have MongoDB Atlas cluster ready

## 2) Prepare backend env locally (you must do)

From `CyberSentinel-Backend` root:

```powershell
copy .env.sample .env
```

Set at least:

```env
APP_ENV=prod
DEBUG_MODE=false
DETAILED_LOGGING=false
MONGO_URI=mongodb+srv://<DB_USER>:<URL_ENCODED_PASSWORD>@<ATLAS_HOST>/?retryWrites=true&w=majority
MONGO_DB=cybersentinel
JWT_SECRET=<LONG_RANDOM_SECRET>
MODEL_DIR=app/ml/models
MODEL_INTEGRITY_REQUIRED=true
ANOMALY_SCORE_THRESHOLD=0.65
```

## 3) Import your trained models into backend format (you must run)

From `CyberSentinel-Backend` root:

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\activate
pip install -r requirements.txt
python scripts\bootstrap_models.py `
  --iforest "..\CyberSentinel-AI\models\isolation_forest.pkl" `
  --rf "..\CyberSentinel-AI\models\random_forest.pkl" `
  --model-dir "app/ml/models" `
  --reason "imported from CyberSentinel-AI"
```

Important:

1. Backend extractor currently emits 5 features.
2. Your CICIDS models were trained on 78 features.
3. If this command fails with feature mismatch, you must retrain models to match backend features before deployment.

## 4) Local verification before cloud (you must run)

```powershell
docker build -f docker/Dockerfile -t cybersentinel-backend:local .
docker run --rm -p 8000:8000 --env-file .env cybersentinel-backend:local
```

Then verify:

1. Open `http://localhost:8000/api/health/`
2. Confirm container logs include model version load and no feature/model errors

## 5) Create AWS ECR repo (you must do once)

Set values:

```powershell
$AWS_REGION="us-east-1"
$AWS_ACCOUNT_ID="<your-account-id>"
$ECR_REPO="cybersentinel-backend"
```

Create repo:

```powershell
aws ecr create-repository --repository-name $ECR_REPO --region $AWS_REGION
```

Login Docker to ECR:

```powershell
aws ecr get-login-password --region $AWS_REGION | docker login --username AWS --password-stdin "$AWS_ACCOUNT_ID.dkr.ecr.$AWS_REGION.amazonaws.com"
```

Build and push image:

```powershell
$IMAGE_TAG="v1"
$IMAGE_URI="$AWS_ACCOUNT_ID.dkr.ecr.$AWS_REGION.amazonaws.com/$ECR_REPO`:$IMAGE_TAG"
docker build -f docker/Dockerfile -t $IMAGE_URI .
docker push $IMAGE_URI
```

## 6) Create ECS Fargate service (you must do in AWS console)

Create:

1. ECS cluster (Fargate)
2. Task definition with one container:
3. Image: `$IMAGE_URI`
4. Port mapping: `8000`
5. CPU/memory: start with `0.5 vCPU / 1 GB`
6. Environment variables: same keys as `.env`
7. Secrets: store `MONGO_URI`, `JWT_SECRET` in Secrets Manager and reference from task

Service:

1. Desired tasks: `1`
2. Attach Application Load Balancer
3. Health check path: `/api/health/`

## 7) Networking and Atlas access (you must do)

1. In ECS security group, allow inbound from ALB to port `8000`
2. In Atlas Network Access, allow ECS egress IP/CIDR (or temporary broad allow for testing)
3. Ensure Atlas user credentials in `MONGO_URI` are correct

## 8) Post-deploy validation (you must run)

1. Open ALB DNS + `/api/health/`
2. Test login and core backend routes
3. Hit `/api/ml/batch-infer` with valid auth token
4. Check CloudWatch logs for startup and inference errors

## 9) What you must do manually vs what is done

Done in code for you:

1. Model registry bootstrap script
2. Inference shape compatibility checks
3. Existing Dockerfile and FastAPI app wiring

Manual actions you must do:

1. AWS account setup and IAM permissions
2. ECR/ECS/ALB creation
3. Secrets Manager values
4. Atlas networking allowlist
5. Real model retraining if feature mismatch occurs

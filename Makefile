# ─────────────────────────────────────────────────────────────────────────────
# EC2 Troubleshooter – Makefile
#
# Run `make help` to see all available targets.
#
# Variables you can override on the command line:
#   IMAGE_NAME   – Docker image name           (default: ec2-troubleshooter)
#   IMAGE_TAG    – Docker image tag            (default: latest)
#   ECR_REGISTRY – ECR registry URL           (default: empty)
#   AWS_REGION   – AWS region for ECR push     (default: us-east-1)
#   S3_BUCKET    – S3 bucket for tar transfer  (default: empty)
#   S3_PREFIX    – S3 key prefix               (default: docker)
# ─────────────────────────────────────────────────────────────────────────────

IMAGE_NAME   ?= ec2-troubleshooter
IMAGE_TAG    ?= latest
ECR_REGISTRY ?=
AWS_REGION   ?= us-east-1
S3_BUCKET    ?=
S3_PREFIX    ?= docker

FULL_IMAGE   := $(IMAGE_NAME):$(IMAGE_TAG)
TAR_FILE     := $(IMAGE_NAME)-$(IMAGE_TAG).tar.gz

# ─────────────────────────────────────────────────────────────────────────────
.PHONY: help build build-offline wheels save load push ecr-login run stop \
        logs shell test clean

help:  ## Show this help message
	@grep -E '^[a-zA-Z_-]+:.*##' $(MAKEFILE_LIST) \
	  | awk 'BEGIN {FS = ":.*## "}; {printf "  \033[36m%-22s\033[0m %s\n", $$1, $$2}'

# ── Build ─────────────────────────────────────────────────────────────────────

build:  ## Build the standard image (requires internet on build host)
	docker build \
	  -f docker/Dockerfile \
	  -t $(FULL_IMAGE) \
	  .
	@echo "Built: $(FULL_IMAGE)"

wheels:  ## Download Python wheels for offline build (requires internet)
	@echo "Downloading wheels into docker/wheels/ ..."
	@mkdir -p docker/wheels
	pip download -r requirements.txt -d docker/wheels/
	@echo "Done. $(shell ls docker/wheels/ | wc -l | tr -d ' ') wheel files downloaded."

build-offline: wheels  ## Build the offline image (wheels baked in, no internet needed after this)
	docker build \
	  -f docker/Dockerfile.offline \
	  -t $(FULL_IMAGE) \
	  .
	@echo "Built offline image: $(FULL_IMAGE)"

# ── Transfer via tar (S3 or manual SCP) ──────────────────────────────────────

save:  ## Save image to a .tar.gz file for offline transfer
	@echo "Saving $(FULL_IMAGE) → $(TAR_FILE) ..."
	docker save $(FULL_IMAGE) | gzip > $(TAR_FILE)
	@echo "Saved: $(TAR_FILE)  ($(shell du -sh $(TAR_FILE) | cut -f1))"

s3-upload:  ## Upload saved tar.gz to S3 (requires S3_BUCKET)
	@test -n "$(S3_BUCKET)" || (echo "ERROR: set S3_BUCKET=your-bucket"; exit 1)
	@test -f "$(TAR_FILE)"  || (echo "ERROR: run 'make save' first"; exit 1)
	aws s3 cp $(TAR_FILE) s3://$(S3_BUCKET)/$(S3_PREFIX)/$(TAR_FILE)
	@echo "Uploaded to: s3://$(S3_BUCKET)/$(S3_PREFIX)/$(TAR_FILE)"

s3-download:  ## Download tar.gz from S3 on the EC2 instance (requires S3_BUCKET)
	@test -n "$(S3_BUCKET)" || (echo "ERROR: set S3_BUCKET=your-bucket"; exit 1)
	aws s3 cp s3://$(S3_BUCKET)/$(S3_PREFIX)/$(TAR_FILE) .
	@echo "Downloaded: $(TAR_FILE)"

load:  ## Load image from tar.gz (run on the air-gapped EC2 instance)
	@test -f "$(TAR_FILE)" || (echo "ERROR: $(TAR_FILE) not found. Run 'make s3-download' first."; exit 1)
	docker load < $(TAR_FILE)
	@echo "Loaded: $(FULL_IMAGE)"

# ── Transfer via ECR ──────────────────────────────────────────────────────────

ecr-login:  ## Authenticate Docker to ECR
	@test -n "$(ECR_REGISTRY)" || (echo "ERROR: set ECR_REGISTRY=123456.dkr.ecr.region.amazonaws.com"; exit 1)
	aws ecr get-login-password --region $(AWS_REGION) \
	  | docker login --username AWS --password-stdin $(ECR_REGISTRY)

push: ecr-login  ## Push image to ECR (requires ECR_REGISTRY)
	docker tag $(FULL_IMAGE) $(ECR_REGISTRY)/$(IMAGE_NAME):$(IMAGE_TAG)
	docker push $(ECR_REGISTRY)/$(IMAGE_NAME):$(IMAGE_TAG)
	@echo "Pushed: $(ECR_REGISTRY)/$(IMAGE_NAME):$(IMAGE_TAG)"

ecr-pull:  ## Pull image from ECR on the EC2 instance (requires ECR_REGISTRY)
	$(MAKE) ecr-login
	docker pull $(ECR_REGISTRY)/$(IMAGE_NAME):$(IMAGE_TAG)
	docker tag $(ECR_REGISTRY)/$(IMAGE_NAME):$(IMAGE_TAG) $(FULL_IMAGE)
	@echo "Pulled and tagged: $(FULL_IMAGE)"

# ── Run ───────────────────────────────────────────────────────────────────────

run:  ## Run the container (reads config from .env)
	@test -f .env || (echo "ERROR: .env not found. Copy .env.example and edit it."; exit 1)
	docker compose -f docker/docker-compose.yml up -d
	@echo "Started. Logs: make logs"

stop:  ## Stop the container
	docker compose -f docker/docker-compose.yml down

restart:  ## Restart the container
	docker compose -f docker/docker-compose.yml restart

logs:  ## Tail container logs
	docker compose -f docker/docker-compose.yml logs -f

shell:  ## Open a shell inside the running container (for debugging)
	docker exec -it ec2-troubleshooter /bin/sh

status:  ## Show container status and health
	docker compose -f docker/docker-compose.yml ps

# ── Dev / test ────────────────────────────────────────────────────────────────

test:  ## Run the test suite
	pytest tests/ -v

clean:  ## Remove build artefacts (wheels, tar files)
	rm -rf docker/wheels/ $(TAR_FILE)
	@echo "Cleaned."

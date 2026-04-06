# ─────────────────────────────────────────────────────────────────────────────
# EC2 Troubleshooter – Makefile
#
# Run `make help` to see all available targets.
#
# Variables (override on command line):
#   IMAGE_NAME   – Docker image name           (default: ec2-troubleshooter)
#   IMAGE_TAG    – Docker image tag            (default: latest)
#   ECR_REGISTRY – ECR registry URL           (default: empty)
#   AWS_REGION   – AWS region for ECR / STS    (default: us-east-1)
#   S3_BUCKET    – S3 bucket for tar transfer  (default: empty)
#   S3_PREFIX    – S3 key prefix               (default: docker)
#   ENV_FILE     – path to .env config file    (default: .env)
#   API_PORT     – host port to bind           (default: 8080)
#   CONTAINER    – container name              (default: ec2-troubleshooter)
# ─────────────────────────────────────────────────────────────────────────────

IMAGE_NAME   ?= ec2-troubleshooter
IMAGE_TAG    ?= latest
ECR_REGISTRY ?=
AWS_REGION   ?= us-east-1
S3_BUCKET    ?=
S3_PREFIX    ?= docker
ENV_FILE     ?= .env
API_PORT     ?= 8080
CONTAINER    ?= ec2-troubleshooter

FULL_IMAGE   := $(IMAGE_NAME):$(IMAGE_TAG)
TAR_FILE     := $(IMAGE_NAME)-$(IMAGE_TAG).tar.gz

# ─────────────────────────────────────────────────────────────────────────────
.PHONY: help build build-offline wheels save s3-upload s3-download load \
        ecr-login push ecr-pull run stop restart logs shell status test clean

help:  ## Show this help message
	@grep -E '^[a-zA-Z_-]+:.*##' $(MAKEFILE_LIST) \
	  | awk 'BEGIN {FS = ":.*## "}; {printf "  \033[36m%-22s\033[0m %s\n", $$1, $$2}'

# ── Build ─────────────────────────────────────────────────────────────────────

build:  ## Build the standard image (requires internet on build host)
	docker build -f docker/Dockerfile -t $(FULL_IMAGE) .
	@echo "Built: $(FULL_IMAGE)"

wheels:  ## Download Python wheels for offline build (requires internet)
	@mkdir -p docker/wheels
	pip download -r requirements.txt -d docker/wheels/
	@echo "Done – $(shell ls docker/wheels/ | wc -l | tr -d ' ') wheels in docker/wheels/"

build-offline: wheels  ## Build the offline image (no internet needed after this step)
	docker build -f docker/Dockerfile.offline -t $(FULL_IMAGE) .
	@echo "Built offline image: $(FULL_IMAGE)"

# ── Transfer via tar + S3 ─────────────────────────────────────────────────────

save:  ## Save image to a compressed tar.gz for transfer
	@echo "Saving $(FULL_IMAGE) → $(TAR_FILE) ..."
	docker save $(FULL_IMAGE) | gzip > $(TAR_FILE)
	@echo "Saved: $(TAR_FILE)  ($(shell du -sh $(TAR_FILE) | cut -f1))"

s3-upload:  ## Upload tar.gz to S3  (requires S3_BUCKET)
	@test -n "$(S3_BUCKET)" || (echo "ERROR: set S3_BUCKET=your-bucket"; exit 1)
	@test -f "$(TAR_FILE)"  || (echo "ERROR: run 'make save' first"; exit 1)
	aws s3 cp $(TAR_FILE) s3://$(S3_BUCKET)/$(S3_PREFIX)/$(TAR_FILE)
	@echo "Uploaded: s3://$(S3_BUCKET)/$(S3_PREFIX)/$(TAR_FILE)"

s3-download:  ## Download tar.gz from S3 on the EC2 instance  (requires S3_BUCKET)
	@test -n "$(S3_BUCKET)" || (echo "ERROR: set S3_BUCKET=your-bucket"; exit 1)
	aws s3 cp s3://$(S3_BUCKET)/$(S3_PREFIX)/$(TAR_FILE) .
	@echo "Downloaded: $(TAR_FILE)"

load:  ## Load image from tar.gz on the EC2 instance
	@test -f "$(TAR_FILE)" || (echo "ERROR: $(TAR_FILE) not found. Run 'make s3-download'."; exit 1)
	docker load < $(TAR_FILE)
	@echo "Loaded: $(FULL_IMAGE)"

# ── Transfer via ECR ──────────────────────────────────────────────────────────

ecr-login:  ## Authenticate Docker to ECR
	@test -n "$(ECR_REGISTRY)" || (echo "ERROR: set ECR_REGISTRY=123456.dkr.ecr.region.amazonaws.com"; exit 1)
	aws ecr get-login-password --region $(AWS_REGION) \
	  | docker login --username AWS --password-stdin $(ECR_REGISTRY)

push: ecr-login  ## Push image to ECR
	docker tag $(FULL_IMAGE) $(ECR_REGISTRY)/$(IMAGE_NAME):$(IMAGE_TAG)
	docker push $(ECR_REGISTRY)/$(IMAGE_NAME):$(IMAGE_TAG)
	@echo "Pushed: $(ECR_REGISTRY)/$(IMAGE_NAME):$(IMAGE_TAG)"

ecr-pull: ecr-login  ## Pull image from ECR on the EC2 instance
	docker pull $(ECR_REGISTRY)/$(IMAGE_NAME):$(IMAGE_TAG)
	docker tag $(ECR_REGISTRY)/$(IMAGE_NAME):$(IMAGE_TAG) $(FULL_IMAGE)
	@echo "Pulled and tagged: $(FULL_IMAGE)"

# ── Run (plain docker run — no docker-compose required) ──────────────────────

run:  ## Start the container using plain docker run (reads ENV_FILE)
	@test -f "$(ENV_FILE)" || (echo "ERROR: $(ENV_FILE) not found. Copy .env.example and edit it."; exit 1)
	docker run -d \
	  --name $(CONTAINER) \
	  --restart unless-stopped \
	  --env-file $(ENV_FILE) \
	  -p $(API_PORT):8080 \
	  --log-driver json-file \
	  --log-opt max-size=50m \
	  --log-opt max-file=5 \
	  $(FULL_IMAGE)
	@echo "Started container '$(CONTAINER)' on port $(API_PORT)"
	@echo "Health: curl http://localhost:$(API_PORT)/health"
	@echo "Logs:   make logs"

stop:  ## Stop and remove the container
	docker stop $(CONTAINER) 2>/dev/null || true
	docker rm   $(CONTAINER) 2>/dev/null || true
	@echo "Stopped: $(CONTAINER)"

restart:  ## Restart the container (stop + run)
	$(MAKE) stop
	$(MAKE) run

logs:  ## Tail container logs
	docker logs -f $(CONTAINER)

shell:  ## Open a shell inside the running container for debugging
	docker exec -it $(CONTAINER) /bin/sh

status:  ## Show container status and recent logs
	@docker inspect $(CONTAINER) --format \
	  'Name: {{.Name}}  State: {{.State.Status}}  Health: {{if .State.Health}}{{.State.Health.Status}}{{else}}n/a{{end}}' \
	  2>/dev/null || echo "Container '$(CONTAINER)' not found"

# ── Dev / test ────────────────────────────────────────────────────────────────

test:  ## Run the test suite
	pytest tests/ -v

clean:  ## Remove build artefacts (wheels directory and tar files)
	rm -rf docker/wheels/ $(TAR_FILE)
	@echo "Cleaned."

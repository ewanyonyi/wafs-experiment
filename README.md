# wafs-experiment

## Build modsecurity nginx image

Adopted from: https://github.com/coreruleset/modsecurity-crs-docker

```bash
docker buildx bake -f docker-bake.hcl --set "*.platform=linux/amd64" nginx-alpine-writable
```
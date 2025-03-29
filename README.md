# wafs-experiment

Build modsecurity nginx image:

```bash
docker buildx bake -f docker-bake.hcl --set "*.platform=linux/amd64" nginx-alpine-writable
```
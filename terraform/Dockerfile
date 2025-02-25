FROM hashicorp/terraform:1.7

WORKDIR /terraform

# Install curl for healthcheck
RUN apk add --no-cache curl

COPY . .

RUN chmod +x entrypoint.sh

ENTRYPOINT ["./entrypoint.sh"]
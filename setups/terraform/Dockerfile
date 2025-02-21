FROM hashicorp/terraform:1.7

WORKDIR /terraform

# Install curl for healthcheck
RUN apk add --no-cache curl

COPY main.tf .
COPY entrypoint.sh .

RUN chmod +x entrypoint.sh

ENTRYPOINT ["./entrypoint.sh"]
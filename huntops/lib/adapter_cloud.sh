#!/usr/bin/env bash
# HuntOps — Cloud Recon Adapter
# Cloud asset discovery and enumeration (AWS, Azure, GCP)
# Output: JSON Lines to stdout for findings sink

set -u
source "$(dirname "${BASH_SOURCE[0]}")/adapter_interface.sh"

# ---- Adapter Contract Implementation ------------------------------------------

adapter_init() {
  mkdir -p "$HUNTOPS_ROOT/output/cloud_recon"
  return 0
}

adapter_name() {
  echo "cloud_recon"
}

adapter_version() {
  echo "1.0.0"
}

adapter_capabilities() {
  echo "recon cloud aws azure gcp buckets iam"
}

adapter_requires_api_key() {
  return 1
}

adapter_is_available() {
  local available=0
  if adapter_tool_exists "cloud_enum"; then
    available=1
  fi
  if adapter_tool_exists "awscli" || adapter_tool_exists "aws"; then
    available=1
  fi
  if adapter_tool_exists "az"; then
    available=1
  fi
  if adapter_tool_exists "gcloud"; then
    available=1
  fi
  if [ $available -eq 0 ]; then
    adapter_warn "No cloud tools found (cloud_enum, awscli, az, gcloud)"
    return 1
  fi
  return 0
}

adapter_health_check() {
  if adapter_tool_exists "cloud_enum"; then
    cloud_enum -h 2>&1 | head -1
  fi
  if adapter_tool_exists "awscli" || adapter_tool_exists "aws"; then
    (awscli --version 2>/dev/null || aws --version 2>/dev/null) | head -1
  fi
  return 0
}

adapter_scan() {
  local target="$1" outdir="$2" opts_json="$3"
  local max_duration threads

  max_duration=$(parse_opt "$opts_json" "max_duration" "600")
  threads=$(parse_opt "$opts_json" "threads" "10")

  # Get live URLs from web probe phase
  local live_urls_file="$outdir/../web/live-urls.txt"
  if [ ! -f "$live_urls_file" ] || [ ! -s "$live_urls_file" ]; then
    adapter_warn "No live URLs found for cloud recon"
    return 0
  fi

  local output_file="$outdir/cloud_recon.txt"
  local count=0

  # Run cloud_enum if available
  if adapter_tool_exists "cloud_enum"; then
    adapter_log "Running cloud_enum for $target"
    local cloud_enum_out="$outdir/cloud_enum.txt"

    timeout -k 30 $max_duration cloud_enum -k "$target" -l "$cloud_enum_out" -t $threads 2>/dev/null

    if [ -f "$cloud_enum_out" ] && [ -s "$cloud_enum_out" ]; then
      while IFS= read -r line; do
        [ -z "$line" ] && continue
        if echo "$line" | grep -qi "bucket\|container\|storage"; then
          local severity="medium"
          if echo "$line" | grep -qi "public\|listable\|open"; then
            severity="high"
          fi
          emit_finding "$severity" "$target" "Cloud storage found: $line" "candidate" \
            "Discovered via cloud_enum" \
            "cloud_enum -k $target" \
            "cloud_enum:storage" "" "cloud,storage,bucket"
          count=$((count + 1))
        elif echo "$line" | grep -qi "iam\|role\|policy\|user"; then
          emit_finding "medium" "$target" "Cloud IAM resource: $line" "candidate" \
            "Discovered via cloud_enum" \
            "cloud_enum -k $target" \
            "cloud_enum:iam" "" "cloud,iam"
          count=$((count + 1))
        elif echo "$line" | grep -qi "dns\|cname\|subdomain"; then
          emit_finding "info" "$target" "Cloud DNS resource: $line" "confirmed" \
            "Discovered via cloud_enum" \
            "cloud_enum -k $target" \
            "cloud_enum:dns" "" "cloud,dns"
          count=$((count + 1))
        fi
      done < "$cloud_enum_out"
    fi
  fi

  # Check for AWS metadata endpoint exposure
  while IFS= read -r url; do
    [ -z "$url" ] && continue
    local host=$(echo "$url" | sed 's|https\?://||' | cut -d/ -f1)

    # Check for AWS IMDSv2
    local aws_meta=$(timeout -k 5 10 curl -sk -H "X-aws-ec2-metadata-token: $(curl -sk -X PUT 'http://169.254.169.254/latest/api/token' -H 'X-aws-ec2-metadata-token-ttl-seconds: 21600')" "http://169.254.169.254/latest/meta-data/" 2>/dev/null | head -5)
    if [ -n "$aws_meta" ]; then
      emit_finding "critical" "$host" "AWS IMDS exposed" "confirmed" \
        "EC2 Instance Metadata Service accessible: $aws_meta" \
        "curl -H 'X-aws-ec2-metadata-token: <token>' http://169.254.169.254/latest/meta-data/" \
        "cloud:aws:imds" "9.0" "cloud,aws,imds,ssrf"
      count=$((count + 1))
    fi

    # Check for GCP metadata
    local gcp_meta=$(timeout -k 5 10 curl -sk -H "Metadata-Flavor: Google" "http://metadata.google.internal/computeMetadata/v1/" 2>/dev/null | head -5)
    if [ -n "$gcp_meta" ]; then
      emit_finding "critical" "$host" "GCP metadata endpoint exposed" "confirmed" \
        "Google Cloud Metadata Service accessible" \
        "curl -H 'Metadata-Flavor: Google' http://metadata.google.internal/computeMetadata/v1/" \
        "cloud:gcp:metadata" "9.0" "cloud,gcp,metadata,ssrf"
      count=$((count + 1))
    fi

    # Check for Azure metadata
    local azure_meta=$(timeout -k 5 10 curl -sk -H "Metadata: true" "http://169.254.169.254/metadata/instance?api-version=2021-02-01" 2>/dev/null | head -5)
    if [ -n "$azure_meta" ]; then
      emit_finding "critical" "$host" "Azure IMDS exposed" "confirmed" \
        "Azure Instance Metadata Service accessible" \
        "curl -H 'Metadata: true' 'http://169.254.169.254/metadata/instance?api-version=2021-02-01'" \
        "cloud:azure:imds" "9.0" "cloud,azure,imds,ssrf"
      count=$((count + 1))
    fi

  done < <(head -10 "$live_urls_file")

  # Check for exposed S3 buckets via DNS
  local subdomain_file="$outdir/../subdomains/resolved.txt"
  if [ -f "$subdomain_file" ] && [ -s "$subdomain_file" ]; then
    while IFS= read -r line; do
      [ -z "$line" ] && continue
      local subdomain=$(echo "$line" | cut -d' ' -f1)

      # Check for S3 bucket patterns
      if echo "$subdomain" | grep -qE '\.s3\.|\.s3-|\.amazonaws\.com$'; then
        local bucket_name=$(echo "$subdomain" | sed 's/\.s3.*//' | sed 's/\.amazonaws\.com$//')
        local test_url="http://$subdomain"

        local resp=$(timeout -k 10 15 curl -skI "$test_url" 2>/dev/null | head -1)
        if echo "$resp" | grep -q "200 OK"; then
          # Try to list bucket
          local list_resp=$(timeout -k 10 15 curl -sk "$test_url" 2>/dev/null)
          if echo "$list_resp" | grep -q "ListBucketResult\|Contents"; then
            emit_finding "critical" "$bucket_name" "S3 bucket publicly listable" "confirmed" \
              "Bucket $bucket_name at $subdomain allows listing" \
              "curl -sk \"$test_url\"" \
              "cloud:s3:listable" "9.5" "cloud,aws,s3,bucket,public"
            count=$((count + 1))
          else
            emit_finding "medium" "$bucket_name" "S3 bucket accessible" "candidate" \
              "Bucket $bucket_name at $subdomain responds but may not be listable" \
              "curl -sk \"$test_url\"" \
              "cloud:s3:accessible" "5.0" "cloud,aws,s3,bucket"
            count=$((count + 1))
          fi
        fi
      fi

      # Check for Azure Blob Storage
      if echo "$subdomain" | grep -qE '\.blob\.core\.windows\.net$'; then
        local account_name=$(echo "$subdomain" | sed 's/\.blob\.core\.windows\.net$//')
        local test_url="https://$subdomain"

        local resp=$(timeout -k 10 15 curl -skI "$test_url" 2>/dev/null | head -1)
        if echo "$resp" | grep -q "200 OK"; then
          emit_finding "high" "$account_name" "Azure Blob Storage accessible" "candidate" \
            "Storage account $account_name at $subdomain accessible" \
            "curl -sk \"$test_url\"" \
            "cloud:azure:blob" "7.0" "cloud,azure,blob,storage"
          count=$((count + 1))
        fi
      fi

      # Check for GCS
      if echo "$subdomain" | grep -qE '\.storage\.googleapis\.com$'; then
        local bucket_name=$(echo "$subdomain" | sed 's/\.storage\.googleapis\.com$//')
        local test_url="https://$subdomain"

        local resp=$(timeout -k 10 15 curl -skI "$test_url" 2>/dev/null | head -1)
        if echo "$resp" | grep -q "200 OK"; then
          emit_finding "high" "$bucket_name" "GCS bucket accessible" "candidate" \
            "GCS bucket $bucket_name at $subdomain accessible" \
            "curl -sk \"$test_url\"" \
            "cloud:gcs:bucket" "7.0" "cloud,gcp,gcs,bucket"
          count=$((count + 1))
        fi
      fi

    done < "$subdomain_file"
  fi

  adapter_log "Cloud recon found $count findings"
  return 0
}

export -f adapter_init adapter_name adapter_version adapter_capabilities
export -f adapter_requires_api_key adapter_is_available adapter_health_check adapter_scan
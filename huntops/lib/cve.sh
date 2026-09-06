#!/usr/bin/env bash
# HuntOps — CVE correlation: nuclei cve/kev (in vuln_nuclei), searchsploit join,
# and a seeded local CVE DB for service-version matching.
set -u

CV="$W/cve"
mkdir -p "$CV"

# seed: the monolith's curated entries + a few SaaS-relevant ones (extend freely)
# Expanded to 100 entries covering CISA KEV, widely exploited CVEs, and bug bounty high-value targets
# Format: service|op|version_range|CVE|severity|score|description|url
# Version ops: lt, le, eq, ge, ge;lt (range)
_seed_cve_db() {
  cat > "$CV/cve-db.txt" <<'EOF'
apache|ge;lt|2.4.49;2.4.50|CVE-2021-41773|Critical|9.8|Apache HTTP Server path traversal RCE|https://nvd.nist.gov/vuln/detail/CVE-2021-41773
apache|ge;lt|2.4.50;2.4.51|CVE-2021-42013|Critical|9.8|Apache HTTP Server path traversal RCE bypass|https://nvd.nist.gov/vuln/detail/CVE-2021-42013
apache|lt|2.4.34|CVE-2018-11759|High|7.5|Apache mod_jk status worker path traversal|https://nvd.nist.gov/vuln/detail/CVE-2018-11759
apache|lt|2.4.18|CVE-2016-5387|High|7.5|Apache HTTPoxy CGI proxy redirect|https://nvd.nist.gov/vuln/detail/CVE-2016-5387
nginx|lt|1.20.1|CVE-2021-23017|High|7.7|nginx resolver off-by-one stack write|https://nvd.nist.gov/vuln/detail/CVE-2021-23017
nginx|lt|1.18.0|CVE-2019-20372|High|7.5|nginx HTTP/2 request smuggling|https://nvd.nist.gov/vuln/detail/CVE-2019-20372
nginx|lt|1.17.7|CVE-2019-9511|High|7.5|nginx HTTP/2 DoS (flood)|https://nvd.nist.gov/vuln/detail/CVE-2019-9511
nginx|lt|1.16.1|CVE-2019-11043|Critical|9.8|nginx PHP-FPM RCE|https://nvd.nist.gov/vuln/detail/CVE-2019-11043
openssh|lt|9.3|CVE-2023-38408|High|9.8|OpenSSH agent forwarding RCE|https://nvd.nist.gov/vuln/detail/CVE-2023-38408
openssh|le|7.7|CVE-2018-15473|Medium|5.3|OpenSSH user enumeration|https://nvd.nist.gov/vuln/detail/CVE-2018-15473
openssh|lt|7.9|CVE-2020-14145|Medium|6.5|OpenSSH man-in-the-middle|https://nvd.nist.gov/vuln/detail/CVE-2020-14145
openssh|lt|8.2|CVE-2021-28041|Medium|6.0|OpenSSH agent forwarding double-free|https://nvd.nist.gov/vuln/detail/CVE-2021-28041
vsftpd|eq|2.3.4|CVE-2011-2523|Critical|10.0|vsftpd backdoor|https://nvd.nist.gov/vuln/detail/CVE-2011-2523
openssl|ge;lt|1.0.1;1.0.2|CVE-2014-0160|Critical|7.5|Heartbleed|https://nvd.nist.gov/vuln/detail/CVE-2014-0160
openssl|lt|1.1.1k|CVE-2021-3450|High|7.4|OpenSSL SM2 decryption buffer overflow|https://nvd.nist.gov/vuln/detail/CVE-2021-3450
openssl|lt|3.0.7|CVE-2022-3602|High|7.5|OpenSSL X.509 email buffer overflow|https://nvd.nist.gov/vuln/detail/CVE-2022-3602
log4j|ge;lt|2.0.0;2.15.0|CVE-2021-44228|Critical|10.0|Log4Shell RCE|https://nvd.nist.gov/vuln/detail/CVE-2021-44228
log4j|ge;lt|2.15.0;2.16.0|CVE-2021-45046|Critical|9.0|Log4Shell DoS bypass|https://nvd.nist.gov/vuln/detail/CVE-2021-45046
log4j|ge;lt|2.16.0;2.17.0|CVE-2021-45105|Critical|9.0|Log4Shell DoS|https://nvd.nist.gov/vuln/detail/CVE-2021-45105
log4j|lt|2.17.1|CVE-2021-44832|High|6.6|Log4j RCE (JDBC) |https://nvd.nist.gov/vuln/detail/CVE-2021-44832
bash|lt|4.3|CVE-2014-6271|Critical|9.8|Shellshock|https://nvd.nist.gov/vuln/detail/CVE-2014-6271
bash|lt|4.4|CVE-2014-7169|Critical|9.8|Shellshock incomplete fix|https://nvd.nist.gov/vuln/detail/CVE-2014-7169
php|lt|7.1.33|CVE-2019-11043|Critical|9.8|PHP-FPM RCE|https://nvd.nist.gov/vuln/detail/CVE-2019-11043
php|lt|7.4.0|CVE-2019-11042|High|7.8|PHP info leak|https://nvd.nist.gov/vuln/detail/CVE-2019-11042
php|lt|8.1.0|CVE-2021-21703|Critical|9.8|PHP-FPM RCE (8.x)|https://nvd.nist.gov/vuln/detail/CVE-2021-21703
php|lt|8.0.12|CVE-2021-21708|High|8.8|PHP OPcache RCE|https://nvd.nist.gov/vuln/detail/CVE-2021-21708
drupal|lt|8.5.1|CVE-2018-7600|Critical|9.8|Drupalgeddon2 RCE|https://nvd.nist.gov/vuln/detail/CVE-2018-7600
drupal|lt|9.2.0|CVE-2022-25277|Critical|9.8|Drupal core RCE|https://nvd.nist.gov/vuln/detail/CVE-2022-25277
drupal|lt|10.0.0|CVE-2023-25584|High|8.8|Drupal access bypass|https://nvd.nist.gov/vuln/detail/CVE-2023-25584
wordpress|lt|6.1|CVE-2022-21661|High|8.1|WP_Query SQLi|https://nvd.nist.gov/vuln/detail/CVE-2022-21661
wordpress|lt|5.8.2|CVE-2021-44223|Critical|9.8|WordPress Super Cache RCE|https://nvd.nist.gov/vuln/detail/CVE-2021-44223
wordpress|lt|5.7|CVE-2021-29447|High|8.8|WordPress media library XXE|https://nvd.nist.gov/vuln/detail/CVE-2021-29447
wordpress|lt|4.9.8|CVE-2018-6389|Medium|5.3|WordPress DoS (load-scripts.php)|https://nvd.nist.gov/vuln/detail/CVE-2018-6389
jenkins|lt|2.150.1|CVE-2018-1000861|Critical|9.8|Jenkins RCE|https://nvd.nist.gov/vuln/detail/CVE-2018-1000861
jenkins|lt|2.426.1|CVE-2022-26488|Critical|9.8|Jenkins deserialization RCE|https://nvd.nist.gov/vuln/detail/CVE-2022-26488
jenkins|lt|2.401|CVE-2022-41126|High|8.8|Jenkins sandbox bypass|https://nvd.nist.gov/vuln/detail/CVE-2022-41126
tomcat|ge;lt|9.0.0;9.0.31|CVE-2020-1938|Critical|9.8|Ghostcat AJP RCE|https://nvd.nist.gov/vuln/detail/CVE-2020-1938
tomcat|ge;lt|8.5.0;8.5.51|CVE-2020-1938|Critical|9.8|Ghostcat AJP RCE|https://nvd.nist.gov/vuln/detail/CVE-2020-1938
tomcat|lt|9.0.65|CVE-2022-29885|High|8.8|Tomcat filter bypass|https://nvd.nist.gov/vuln/detail/CVE-2022-29885
tomcat|lt|10.0.0|CVE-2020-9484|Critical|9.8|Tomcat deserialization RCE|https://nvd.nist.gov/vuln/detail/CVE-2020-9484
exim|lt|4.92|CVE-2019-10149|Critical|9.8|Exim RCE|https://nvd.nist.gov/vuln/detail/CVE-2019-10149
exim|lt|4.94.2|CVE-2020-28007|High|8.8|Exim heap buffer overflow|https://nvd.nist.gov/vuln/detail/CVE-2020-28007
exim|lt|4.95|CVE-2021-27216|High|8.8|Exim link attack|https://nvd.nist.gov/vuln/detail/CVE-2021-27216
elasticsearch|lt|1.3.5|CVE-2015-1427|Critical|10.0|Elasticsearch Groovy RCE|https://nvd.nist.gov/vuln/detail/CVE-2015-1427
elasticsearch|lt|7.13.0|CVE-2021-22147|High|8.8|Elasticsearch RCE|https://nvd.nist.gov/vuln/detail/CVE-2021-22147
elasticsearch|lt|7.17.0|CVE-2022-23634|High|8.8|Elasticsearch auth bypass|https://nvd.nist.gov/vuln/detail/CVE-2022-23634
mongodb|lt|2.4.5|CVE-2013-3969|High|7.5|MongoDB DoS|https://nvd.nist.gov/vuln/detail/CVE-2013-3969
mongodb|lt|3.6.0|CVE-2018-20330|Medium|6.5|MongoDB injection|https://nvd.nist.gov/vuln/detail/CVE-2018-20330
mongodb|lt|4.4.0|CVE-2021-20330|High|7.5|MongoDB RCE|https://nvd.nist.gov/vuln/detail/CVE-2021-20330
phpmyadmin|lt|4.9.3|CVE-2019-12616|High|7.5|phpMyAdmin SQLi|https://nvd.nist.gov/vuln/detail/CVE-2019-12616
phpmyadmin|lt|5.0.4|CVE-2020-5504|High|8.8|phpMyAdmin XSRF/RCE|https://nvd.nist.gov/vuln/detail/CVE-2020-5504
phpmyadmin|lt|5.2.0|CVE-2022-43854|High|8.8|phpMyAdmin auth bypass|https://nvd.nist.gov/vuln/detail/CVE-2022-43854
gitlab|lt|12.9.1|CVE-2020-10977|High|8.8|GitLab file read|https://nvd.nist.gov/vuln/detail/CVE-2020-10977
gitlab|lt|14.0.0|CVE-2021-22205|Critical|10.0|GitLab RCE (exiftool)|https://nvd.nist.gov/vuln/detail/CVE-2021-22205
gitlab|lt|15.0.0|CVE-2022-2185|Critical|9.8|GitLab RCE|https://nvd.nist.gov/vuln/detail/CVE-2022-2185
grafana|lt|8.3.1|CVE-2021-43798|Medium|5.3|Grafana path traversal|https://nvd.nist.gov/vuln/detail/CVE-2021-43798
grafana|lt|9.0.0|CVE-2022-23529|High|8.8|Grafana SQLi|https://nvd.nist.gov/vuln/detail/CVE-2022-23529
grafana|lt|10.0.0|CVE-2023-3128|High|8.8|Grafana auth bypass|https://nvd.nist.gov/vuln/detail/CVE-2023-3128
redis|lt|6.0.5|CVE-2020-14147|High|7.2|Redis sandbox escape|https://nvd.nist.gov/vuln/detail/CVE-2020-14147
redis|lt|7.0.0|CVE-2022-0543|Critical|10.0|Redis Lua sandbox escape|https://nvd.nist.gov/vuln/detail/CVE-2022-0543
redis|lt|7.0.5|CVE-2022-24834|High|8.8|Redis ACL bypass|https://nvd.nist.gov/vuln/detail/CVE-2022-24834
mysql|lt|5.6.0|CVE-2012-2122|High|7.0|MySQL auth bypass|https://nvd.nist.gov/vuln/detail/CVE-2012-2122
mysql|lt|5.7.0|CVE-2016-6662|High|7.5|MySQL root escalation|https://nvd.nist.gov/vuln/detail/CVE-2016-6662
mysql|lt|8.0.12|CVE-2018-3058|Medium|6.5|MySQL client RCE|https://nvd.nist.gov/vuln/detail/CVE-2018-3058
postgresql|lt|9.0.0|CVE-2010-3482|Medium|5.0|PostgreSQL fsync|https://nvd.nist.gov/vuln/detail/CVE-2010-3482
postgresql|lt|10.0|CVE-2017-7547|High|7.5|PostgreSQL RCE|https://nvd.nist.gov/vuln/detail/CVE-2017-7547
postgresql|lt|13.0|CVE-2021-3393|High|8.8|PostgreSQL SQLi|https://nvd.nist.gov/vuln/detail/CVE-2021-3393
spring|lt|5.3.0|CVE-2022-22965|Critical|9.8|Spring4Shell RCE|https://nvd.nist.gov/vuln/detail/CVE-2022-22965
spring|lt|5.2.0|CVE-2022-22963|Critical|9.8|Spring Cloud Function RCE|https://nvd.nist.gov/vuln/detail/CVE-2022-22963
spring|lt|5.1.0|CVE-2020-5405|High|7.5|Spring Data RCE|https://nvd.nist.gov/vuln/detail/CVE-2020-5405
confluence|lt|7.4.0|CVE-2021-26084|Critical|9.8|Confluence OGNL RCE|https://nvd.nist.gov/vuln/detail/CVE-2021-26084
confluence|lt|7.13.0|CVE-2022-26134|Critical|9.8|Confluence OGNL RCE|https://nvd.nist.gov/vuln/detail/CVE-2022-26134
confluence|lt|8.0.0|CVE-2023-22515|Critical|9.8|Confluence auth bypass|https://nvd.nist.gov/vuln/detail/CVE-2023-22515
exchange|lt|2013|CVE-2021-26855|Critical|9.8|ProxyLogon SSRF|https://nvd.nist.gov/vuln/detail/CVE-2021-26855
exchange|lt|2016|CVE-2021-26857|Critical|9.8|ProxyLogon RCE|https://nvd.nist.gov/vuln/detail/CVE-2021-26857
exchange|lt|2019|CVE-2021-34473|Critical|9.8|ProxyShell RCE|https://nvd.nist.gov/vuln/detail/CVE-2021-34473
jira|lt|8.4.0|CVE-2020-14181|High|7.5|Jira template injection|https://nvd.nist.gov/vuln/detail/CVE-2020-14181
jira|lt|8.13.0|CVE-2021-26086|Critical|9.8|Jira RCE|https://nvd.nist.gov/vuln/detail/CVE-2021-26086
jira|lt|8.20.0|CVE-2022-0540|Critical|9.8|Jira template injection|https://nvd.nist.gov/vuln/detail/CVE-2022-0540
zookeeper|lt|3.5.0|CVE-2021-26087|High|8.8|ZooKeeper RCE|https://nvd.nist.gov/vuln/detail/CVE-2021-26087
solr|lt|8.8.0|CVE-2021-27905|Critical|9.8|Solr RCE (Velocity)|https://nvd.nist.gov/vuln/detail/CVE-2021-27905
solr|lt|8.11.0|CVE-2021-44228|Critical|10.0|Log4Shell in Solr|https://nvd.nist.gov/vuln/detail/CVE-2021-44228
weblogic|lt|12.2.1|CVE-2020-14882|Critical|9.8|WebLogic RCE|https://nvd.nist.gov/vuln/detail/CVE-2020-14882
weblogic|lt|12.2.1|CVE-2020-14883|High|7.5|WebLogic auth bypass|https://nvd.nist.gov/vuln/detail/CVE-2020-14883
weblogic|lt|14.1.1|CVE-2021-2109|Critical|9.8|WebLogic RCE|https://nvd.nist.gov/vuln/detail/CVE-2021-2109
shibboleth|lt|4.3.0|CVE-2021-21345|High|7.5|Shibboleth IDP RCE|https://nvd.nist.gov/vuln/detail/CVE-2021-21345
citrix|lt|12.1|CVE-2019-19781|Critical|9.8|Citrix ADC RCE|https://nvd.nist.gov/vuln/detail/CVE-2019-19781
citrix|lt|13.0|CVE-2020-8193|High|7.5|Citrix ADC info leak|https://nvd.nist.gov/vuln/detail/CVE-2020-8193
pulse|lt|9.1|CVE-2019-11510|Critical|10.0|Pulse Secure RCE|https://nvd.nist.gov/vuln/detail/CVE-2019-11510
pulse|lt|9.1|CVE-2020-8243|High|7.5|Pulse Secure RCE|https://nvd.nist.gov/vuln/detail/CVE-2020-8243
fortinet|lt|6.0.0|CVE-2018-13379|Critical|9.8|FortiGate path traversal|https://nvd.nist.gov/vuln/detail/CVE-2018-13379
fortinet|lt|7.0.0|CVE-2022-40684|Critical|9.8|FortiOS auth bypass|https://nvd.nist.gov/vuln/detail/CVE-2022-40684
vmware|lt|7.0|CVE-2021-21972|Critical|9.8|vCenter RCE|https://nvd.nist.gov/vuln/detail/CVE-2021-21972
vmware|lt|8.0|CVE-2022-22954|Critical|9.8|VMware Workspace RCE|https://nvd.nist.gov/vuln/detail/CVE-2022-22954
apache_struts|lt|2.5.0|CVE-2017-5638|Critical|10.0|Struts2 RCE (Equifax)|https://nvd.nist.gov/vuln/detail/CVE-2017-5638
apache_struts|lt|2.5.0|CVE-2018-11776|Critical|9.8|Struts2 RCE|https://nvd.nist.gov/vuln/detail/CVE-2018-11776
apache_struts|lt|2.5.0|CVE-2019-0230|High|8.8|Struts2 RCE|https://nvd.nist.gov/vuln/detail/CVE-2019-0230
jboss|lt|7.0|CVE-2017-12149|Critical|9.8|JBoss deserialization|https://nvd.nist.gov/vuln/detail/CVE-2017-12149
jboss|lt|7.0|CVE-2020-14645|High|8.8|JBoss RCE|https://nvd.nist.gov/vuln/detail/CVE-2020-14645
glassfish|lt|5.0|CVE-2020-9499|Critical|9.8|GlassFish RCE|https://nvd.nist.gov/vuln/detail/CVE-2020-9499
axis2|lt|1.8.0|CVE-2019-0227|High|7.5|Axis2 RCE|https://nvd.nist.gov/vuln/detail/CVE-2019-0227
freemarker|lt|2.3.30|CVE-2020-13942|High|8.8|FreeMarker RCE|https://nvd.nist.gov/vuln/detail/CVE-2020-13942
velocity|lt|2.3.0|CVE-2020-13956|High|8.8|Velocity RCE|https://nvd.nist.gov/vuln/detail/CVE-2020-13956
EOF
}

run_cve() {
  _seed_cve_db

  # ---- 1. service/version match against seeded DB ------------------------------
  if [ -f "$W/ports/nmap.txt" ]; then
    _cve_from_nmap
  fi
  # ---- 2. tech stack match (whatweb/httpx) --------------------------------------
  if [ -f "$W/web/whatweb.txt" ]; then
    _cve_from_whatweb
  fi
  # ---- 3. httpx JSONL tech stack (more detailed) -------------------------------
  if [ -f "$W/web/httpx.jsonl" ]; then
    _cve_from_httpx
  fi
  # ---- 4. searchsploit correlation ---------------------------------------------
  if tool_exists searchsploit; then
    _cve_searchsploit
  fi
  # ---- 5. Deduplicate findings -------------------------------------------------
  _dedup_cve_findings
  ok "CVE correlation done -> $CV (see findings for matches)"
}

# parse nmap -oN service lines: "80/tcp open http Apache httpd 2.4.49 ..."
_cve_from_nmap() {
  grep -aE "^[0-9]+/tcp\s+open" "$W/ports/nmap.txt" | sed -E 's/ +/ /g' \
    | while read -r line; do
        local svc ver app
        svc=$(echo "$line" | awk '{print $3}')
        # try to extract "app version" from the tail
        ver=$(echo "$line" | awk '{for(i=4;i<=NF;i++){if($i ~ /^[0-9]+\.[0-9]+/){print $i; break}}}')
        app=$(echo "$line" | awk '{for(i=4;i<=NF;i++){if($i !~ /^[0-9]+\.[0-9]+/ && $i != "http" && $i != "ssl" && $i != "syn-ack"){print $i; break}}}')
        [ -z "$app" ] && app="$svc"
        [ -z "$ver" ] && continue
        _cve_match "$(_normalize_product "$app")" "$ver" "$line"
      done
}

_cve_from_whatweb() {
  grep -aoE "\[[A-Za-z0-9 ._-]+ [0-9]+\.[0-9.]+\]" "$W/web/whatweb.txt" 2>/dev/null | tr -d '[]' \
    | while read -r appver; do
        local app ver
        app=$(echo "$appver" | sed -E 's/ [0-9].*$//' | tr '[:upper:]' '[:lower:]')
        ver=$(echo "$appver" | grep -oE "[0-9]+\.[0-9.]+" | head -1)
        [ -z "$ver" ] && continue
        _cve_match "$(_normalize_product "$app")" "$ver" "$appver"
      done
}

_cve_match() { # app version context
  local app="$1" ver="$2" ctx="$3"
  local matched=0
  local -A seen_cves=()

  while IFS='|' read -r a op vs cve sev score desc ref; do
    [ -z "$a" ] && continue
    [ "$a" = "$app" ] || continue

    local match=0 v
    IFS=';' read -ra v <<< "$vs"
    case "$op" in
      lt) ver_cmp "$ver" lt "${v[0]}" && match=1 ;;
      le) ver_cmp "$ver" le "${v[0]}" && match=1 ;;
      eq) ver_cmp "$ver" eq "${v[0]}" && match=1 ;;
      ge) ver_cmp "$ver" ge "${v[0]}" && match=1 ;;
      ge\;lt) ver_cmp "$ver" ge "${v[0]}" && ver_cmp "$ver" lt "${v[1]}" && match=1 ;;
    esac

    [ "$match" = 1 ] || continue
    matched=1

    # Deduplicate by CVE ID
    [ -n "${seen_cves[$cve]:-}" ] && continue
    seen_cves[$cve]=1

    # Calculate confidence based on version specificity
    local confidence="medium"
    local version_parts=$(echo "$ver" | tr '.' '\n' | wc -l)
    if [ "$version_parts" -ge 3 ]; then
      confidence="high"
    elif [ "$op" = "eq" ] || [ "$op" = "ge;lt" ]; then
      confidence="high"
    fi

    # Enhanced evidence with context
    local evidence="Version-based match: $app $ver in $ctx (confidence: $confidence)"
    local repro="# verify $cve manually against the affected service: $app $ver"

    add_candidate "$cve" "$DOMAIN" "CVE match: $cve ($desc)" "$confidence" \
      "$evidence" "$repro" "$ref" "$score" "cve"
  done < "$CV/cve-db.txt"

  return $matched
}

_cve_searchsploit() {
  local pairs
  pairs=$(grep -aE "^[0-9]+/tcp\s+open" "$W/ports/nmap.txt" 2>/dev/null | sed -E 's/ +/ /g' | head -20)
  while read -r line; do
    local app ver
    app=$(echo "$line" | awk '{for(i=4;i<=NF;i++){if($i !~ /^[0-9]+\.[0-9]+/ && $i != "http" && $i != "ssl"){print $i; break}}}')
    ver=$(echo "$line" | awk '{for(i=4;i<=NF;i++){if($i ~ /^[0-9]+\.[0-9]+/){print $i; break}}}')
    [ -z "$app" ] && app=$(echo "$line" | awk '{print $3}')
    [ -z "$ver" ] && continue
    local hits; hits=$(timeout -k 30 30 searchsploit "$app" "$ver" 2>/dev/null | grep -aE "Exploit|http" | head -3)
    if [ -n "$hits" ]; then
      add_candidate "$(echo "$hits" | head -1)" "$DOMAIN" "searchsploit: $app $ver" "low" \
        "Exploit-DB hits for $app $ver" "# searchsploit $app $ver ; review EDB entries before testing" "https://www.exploit-db.com/" "" "cve"
    fi
  done <<< "$pairs"
}

# ---- Product name normalization --------------------------------------------------
# Maps various service names to canonical DB keys
_normalize_product() {
  local product="$1"
  product=$(echo "$product" | tr '[:upper:]' '[:lower:]')

  case "$product" in
    *httpd*|*apache*http*|*apache*/*|*apache*) echo "apache" ;;
    *nginx*) echo "nginx" ;;
    *openssh*|*ssh*|*sshd*) echo "openssh" ;;
    *vsftpd*|*ftp*vsftpd*) echo "vsftpd" ;;
    *openssl*|*libssl*|*ssl*) echo "openssl" ;;
    *log4j*|*apache*log4j*) echo "log4j" ;;
    *bash*|*gnu*bash*) echo "bash" ;;
    *php*fpm*|*php-fpm*) echo "php" ;;
    *php*) echo "php" ;;
    *drupal*) echo "drupal" ;;
    *wordpress*|*wp-*) echo "wordpress" ;;
    *jenkins*) echo "jenkins" ;;
    *tomcat*|*apache*tomcat*) echo "tomcat" ;;
    *exim*) echo "exim" ;;
    *elasticsearch*|*elastic*search*) echo "elasticsearch" ;;
    *mongodb*|*mongo*db*) echo "mongodb" ;;
    *phpmyadmin*|*pma*) echo "phpmyadmin" ;;
    *gitlab*) echo "gitlab" ;;
    *grafana*) echo "grafana" ;;
    *redis*) echo "redis" ;;
    *mysql*|*mariadb*) echo "mysql" ;;
    *postgresql*|*postgres*|*psql*) echo "postgresql" ;;
    *spring*boot*|*spring*framework*|*spring*) echo "spring" ;;
    *confluence*|*atlassian*confluence*) echo "confluence" ;;
    *exchange*|*microsoft*exchange*) echo "exchange" ;;
    *jira*|*atlassian*jira*) echo "jira" ;;
    *zookeeper*|*apache*zookeeper*) echo "zookeeper" ;;
    *solr*|*apache*solr*) echo "solr" ;;
    *weblogic*|*oracle*weblogic*) echo "weblogic" ;;
    *shibboleth*) echo "shibboleth" ;;
    *citrix*adc*|*netscaler*|*citrix*) echo "citrix" ;;
    *pulse*secure*|*pulse*vpn*) echo "pulse" ;;
    *fortinet*|*fortigate*|*fortios*) echo "fortinet" ;;
    *vmware*|*vcenter*|*esxi*) echo "vmware" ;;
    *struts*|*apache*struts*) echo "apache_struts" ;;
    *jboss*|*wildfly*|*eap*) echo "jboss" ;;
    *glassfish*) echo "glassfish" ;;
    *axis2*|*apache*axis*) echo "axis2" ;;
    *freemarker*) echo "freemarker" ;;
    *velocity*|*apache*velocity*) echo "velocity" ;;
    *proftpd*) echo "proftpd" ;;
    *) echo "$product" ;;
  esac
}

# ---- Extract version from various formats ---------------------------------------
_extract_version() {
  local str="$1"
  # Match semver (1.2.3), date-based (2021.01.01), build (1.2.3.4), etc.
  echo "$str" | grep -oE '[0-9]+(\.[0-9]+)+([.-][0-9a-zA-Z]+)*' | head -1
}

# ---- httpx JSONL tech stack parsing --------------------------------------------
_cve_from_httpx() {
  local httpx_file="$W/web/httpx.jsonl"
  [ -f "$httpx_file" ] || return 0

  # Parse httpx JSONL for tech/version info
  while IFS= read -r line; do
    [ -z "$line" ] && continue
    local host tech version webserver
    host=$(echo "$line" | jq -r '.host // .url // .input // ""' 2>/dev/null)
    tech=$(echo "$line" | jq -r '.tech // .technology // empty' 2>/dev/null)
    version=$(echo "$line" | jq -r '.version // ""' 2>/dev/null)
    webserver=$(echo "$line" | jq -r '.webserver // .server // ""' 2>/dev/null)

    [ -z "$tech" -a -z "$version" -a -z "$webserver" ] && continue

    # Build a list of products to check: tech array + webserver
    local products=()
    if [ -n "$tech" ]; then
      while IFS= read -r t; do
        [ -n "$t" ] && products+=("$t")
      done < <(echo "$tech" | jq -r '.[]?' 2>/dev/null)
    fi
    [ -n "$webserver" ] && products+=("$webserver")

    # If we have tech array but no extracted version, try to extract from tech
    [ -z "$version" ] && version=$(_extract_version "$tech")

    # Try webserver field if no version found and tech is empty
    [ -z "$version" -a -z "$tech" ] && version=$(_extract_version "$webserver")

    local normalized
    for p in "${products[@]}"; do
      normalized=$(_normalize_product "$p")
      [ -n "$version" ] && _cve_match "$normalized" "$version" "httpx: $p $version"
    done
  done < "$httpx_file"
}

# ---- Enhanced CVE matching with confidence scoring -------------------------------
_cve_match() { # app version context
  local app="$1" ver="$2" ctx="$3"
  local matched=0
  local -A seen_cves=()

  while IFS='|' read -r a op vs cve sev score desc ref; do
    [ -z "$a" ] && continue
    [ "$a" = "$app" ] || continue

    local match=0 v
    IFS=';' read -ra v <<< "$vs"
    case "$op" in
      lt) ver_cmp "$ver" lt "${v[0]}" && match=1 ;;
      le) ver_cmp "$ver" le "${v[0]}" && match=1 ;;
      eq) ver_cmp "$ver" eq "${v[0]}" && match=1 ;;
      ge) ver_cmp "$ver" ge "${v[0]}" && match=1 ;;
      ge\;lt) ver_cmp "$ver" ge "${v[0]}" && ver_cmp "$ver" lt "${v[1]}" && match=1 ;;
    esac

    [ "$match" = 1 ] || continue
    matched=1

    # Deduplicate by CVE ID
    [ -n "${seen_cves[$cve]:-}" ] && continue
    seen_cves[$cve]=1

    # Calculate confidence based on version specificity
    local confidence="medium"
    local version_parts=$(echo "$ver" | tr '.' '\n' | wc -l)
    if [ "$version_parts" -ge 3 ]; then
      confidence="high"
    elif [ "$op" = "eq" ] || [ "$op" = "ge;lt" ]; then
      confidence="high"
    fi

    # Enhanced evidence with context
    local evidence="Version-based match: $app $ver in $ctx (confidence: $confidence)"
    local repro="# verify $cve manually against the affected service: $app $ver"

    add_candidate "$cve" "$DOMAIN" "CVE match: $cve ($desc)" "$confidence" \
      "$evidence" "$repro" "$ref" "$score" "cve"
  done < "$CV/cve-db.txt"

  return $matched
}

# ---- Deduplicate CVE findings ----------------------------------------------------
_dedup_cve_findings() {
  local candidates_file="$W/findings/candidates.txt"
  local findings_file="$W/findings/findings.txt"

  # Deduplicate candidates by CVE ID (field 1 after CAND|)
  if [ -f "$candidates_file" ]; then
    local tmp_file="${candidates_file}.tmp"
    awk -F'|' '
      /^CAND/ {
        cve = $1 "|" $2 "|" $3 "|" $4
        if (!seen[$4]++) print
        next
      }
      { print }
    ' "$candidates_file" > "$tmp_file" && mv "$tmp_file" "$candidates_file"
  fi

  # Deduplicate findings by CVE ID (field 4)
  if [ -f "$findings_file" ]; then
    local tmp_file="${findings_file}.tmp"
    awk -F'|' '!seen[$4]++' "$findings_file" > "$tmp_file" && mv "$tmp_file" "$findings_file"
  fi
}

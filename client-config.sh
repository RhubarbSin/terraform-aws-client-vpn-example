set -e

eval "$(jq -r '@sh "region=\(.region) client_vpn_endpoint_id=\(.client_vpn_endpoint_id)"')"

aws ec2 export-client-vpn-client-configuration \
    --region "${region}" \
    --client-vpn-endpoint-id "${client_vpn_endpoint_id}"

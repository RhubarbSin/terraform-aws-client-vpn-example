set -e

eval "$(jq -r '@sh "region=\(.region) s3_uri=\(.s3_uri)"')"

url="$(aws s3 presign --expires-in 86400 --region ${region} ${s3_uri})"

jq -n --arg url "$url" '{"url":$url}'

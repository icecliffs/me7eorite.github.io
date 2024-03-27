# Writenup

## BadAss Server for Hypertext

```bash
#!/bin/bash

# I hope there are no bugs in this source code...

set -e

declare -A request_headers
declare -A response_headers
declare method
declare uri
declare protocol
declare request_body
declare status="200 OK"

abort() {
	declare -gA response_headers
	status="400 Bad Request"
	write_headers
	if [ ! -z ${1+x} ]; then
		>&2 echo "Request aborted: $1"
		echo -en $1
	fi
	exit 1
}

write_headers() {
	response_headers['Connection']='close'
	response_headers['X-Powered-By']='Bash'

	echo -en "HTTP/1.0 $status\r\n"

	for key in "${!response_headers[@]}"; do
		echo -en "${key}: ${response_headers[$key]}\r\n"
	done

	echo -en '\r\n'

	>&2 echo "$(date -u +'%Y-%m-%dT%H:%M:%SZ') $SOCAT_PEERADDR $method $uri $protocol -> $status"
}

receive_request() {
	read -d $'\n' -a request_line

	if [ ${#request_line[@]} != 3 ]; then
		abort "Invalid request line"
	fi

	method=${request_line[0]}

	uri=${request_line[1]}

	protocol=$(echo -n "${request_line[2]}" | sed 's/^\s*//g' | sed 's/\s*$//g')

	if [[ ! $method =~ ^(GET|HEAD)$ ]]; then
		abort "Invalid request method"
	fi

	if [[ ! $uri =~ ^/ ]]; then
		abort 'Invalid URI'
	fi

	if [ $protocol != 'HTTP/1.0' ] && [ $protocol != 'HTTP/1.1' ]; then
		abort 'Invalid protocol'
	fi

	while read -d $'\n' header; do
		stripped_header=$(echo -n "$header" | sed 's/^\s*//g' | sed 's/\s*$//g')

		if [ -z "$stripped_header" ]; then
			break;
		fi

		header_name=$(echo -n "$header" | cut -d ':' -f 1 | sed 's/^\s*//g' | sed 's/\s*$//g' | tr '[:upper:]' '[:lower:]');
		header_value=$(echo -n "$header" | cut -d ':' -f 2- | sed 's/^\s*//g' | sed 's/\s*$//g');

		if [ -z "$header_name" ] || [[ "$header_name" =~ [[:space:]] ]]; then
			abort "Invalid header name";
		fi

		# If header already exists, add value to comma separated list
		if [[ -v request_headers[$header_name] ]]; then
			request_headers[$header_name]="${request_headers[$header_name]}, $header_value"
		else
			request_headers[$header_name]="$header_value"
		fi
	done

	body_length=${request_headers["content-length"]:-0}

	if [[ ! $body_length =~ ^[0-9]+$ ]]; then
		abort "Invalid Content-Length"
	fi

	read -N $body_length request_body
}

handle_request() {
	# Default: serve from static directory
	path="/app/static$uri"
	path_last_character=$(echo -n "$path" | tail -c 1)

	if [ "$path_last_character" == '/' ]; then
		path="${path}index.html"
	fi

	if ! cat "$path" > /dev/null; then
		status="404 Not Found"
	else
		mime_type=$(file --mime-type -b "$path")
		file_size=$(stat --printf="%s" "$path")

		response_headers["Content-Type"]="$mime_type"
		response_headers["Content-Length"]="$file_size"
	fi

	write_headers

	cat "$path" 2>&1
}

receive_request
handle_request
```





## One key to rule them all
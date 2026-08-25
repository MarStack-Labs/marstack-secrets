#!/bin/sh
set -eu

module_path='github.com/marstack-labs/marstack-secrets'
failed=0

report() {
	echo "$1"
	echo "$2"
	failed=1
}

cross_module=$(grep -rn "$module_path/internal/modules/" internal/modules --include='*.go' || true)
if [ -n "$cross_module" ]; then
	report "modules must not import other modules, they communicate through the composition root:" "$cross_module"
fi

module_to_app=$(grep -rn "$module_path/internal/app" internal/modules --include='*.go' || true)
if [ -n "$module_to_app" ]; then
	report "modules must not import the composition root:" "$module_to_app"
fi

platform_upwards=$(grep -rnE "$module_path/internal/(modules|app)" internal/platform --include='*.go' || true)
if [ -n "$platform_upwards" ]; then
	report "platform packages must not depend on modules or the composition root:" "$platform_upwards"
fi

client_downwards=$(grep -rnE "$module_path/internal/(modules|app)" internal/client --include='*.go' || true)
if [ -n "$client_downwards" ]; then
	report "the client must not depend on modules or the composition root:" "$client_downwards"
fi

agent_downwards=$(grep -rnE "$module_path/internal/(modules|app)" internal/agent --include='*.go' || true)
if [ -n "$agent_downwards" ]; then
	report "the agent must not depend on modules or the composition root:" "$agent_downwards"
fi

server_to_client=$(grep -rnE "$module_path/internal/(client|agent)" internal/modules internal/platform internal/app --include='*.go' || true)
if [ -n "$server_to_client" ]; then
	report "the server must not depend on its own client or agent:" "$server_to_client"
fi

if [ "$failed" -ne 0 ]; then
	exit 1
fi

echo "architecture boundaries ok"

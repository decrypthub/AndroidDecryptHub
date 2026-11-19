#!/system/bin/sh
# The module installer and the isolated upgrade check use this same initializer.
set -eu

data_dir=$1
scope_file="$data_dir/scope.json"
mkdir -p "$data_dir"

# An upgrade retains the existing file, including fields this version does not read.
if [ ! -e "$scope_file" ] && [ ! -L "$scope_file" ]; then
  (set -C; printf '%s\n' '{"version":1,"mode":"allowlist","packages":[]}' > "$scope_file")
fi

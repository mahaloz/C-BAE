#!/usr/bin/env bash
set -euo pipefail

# The host orchestrator runs the container with the invoking non-root UID/GID so
# its mode-0700 bind mounts stay private and writable on native Linux. Give that
# numeric identity an in-container passwd/group entry without modifying the
# read-only root filesystem.
current_uid=$(id -u)
current_gid=$(id -g)
if ! getent passwd "$current_uid" >/dev/null; then
    passwd_file=/tmp/zion-eval.passwd
    group_file=/tmp/zion-eval.group
    cp /etc/passwd "$passwd_file"
    cp /etc/group "$group_file"
    if ! getent group "$current_gid" >/dev/null; then
        printf 'zion-host:x:%s:\n' "$current_gid" >>"$group_file"
    fi
    printf 'zion-runtime:x:%s:%s:Zion runtime:/work:/bin/bash\n' \
        "$current_uid" "$current_gid" >>"$passwd_file"
    export NSS_WRAPPER_PASSWD=$passwd_file
    export NSS_WRAPPER_GROUP=$group_file
    export LD_PRELOAD=/usr/lib/x86_64-linux-gnu/libnss_wrapper.so
    export USER=zion-runtime LOGNAME=zion-runtime

    # The image's declared HOME belongs to its built-in UID and may be
    # inaccessible (and read-only) when the orchestrator maps the host user.
    # DecLib probes user-specific plugin paths even before an evaluation stage
    # installs its isolated /state HOME, so provide a safe bootstrap home.
    runtime_home=/tmp/zion-runtime-home
    install -d -m 0700 \
        "$runtime_home" \
        "$runtime_home/cache" \
        "$runtime_home/config" \
        "$runtime_home/data"
    export HOME=$runtime_home
    export XDG_CACHE_HOME=$runtime_home/cache
    export XDG_CONFIG_HOME=$runtime_home/config
    export XDG_DATA_HOME=$runtime_home/data
fi

if (($# == 0)); then
    exec zion-eval --help
fi

if [[ $1 == "smoke-test" ]]; then
    shift
    exec zion-runtime-smoke "$@"
fi

# Accept both `docker run IMAGE run ...` and the more explicit
# `docker run IMAGE zion-eval run ...` form.
if [[ $1 == "zion-eval" ]]; then
    shift
fi

exec zion-eval "$@"

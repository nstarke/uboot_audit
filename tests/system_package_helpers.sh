#!/bin/sh

set -u

ela_command_exists() {
    command -v "$1" >/dev/null 2>&1
}

ela_detect_package_manager() {
    if [ -r /etc/os-release ]; then
        ela_os_id="$(sed -n 's/^ID=//p' /etc/os-release | head -n 1 | tr -d '"')"
        ela_os_like="$(sed -n 's/^ID_LIKE=//p' /etc/os-release | head -n 1 | tr -d '"')"
    else
        ela_os_id=""
        ela_os_like=""
    fi

    for ela_candidate in apt-get dnf yum zypper pacman apk; do
        if ela_command_exists "$ela_candidate"; then
            case "$ela_candidate" in
                apt-get)
                    echo apt
                    return 0
                    ;;
                *)
                    echo "$ela_candidate"
                    return 0
                    ;;
            esac
        fi
    done

    case " $ela_os_id $ela_os_like " in
        *" debian "*|*" ubuntu "*) echo apt ; return 0 ;;
        *" fedora "*|*" rhel "*|*" centos "*|*" rocky "*|*" almalinux "*)
            if ela_command_exists dnf; then
                echo dnf
            else
                echo yum
            fi
            return 0
            ;;
        *" opensuse "*|*" suse "*|*" sles "*) echo zypper ; return 0 ;;
        *" arch "*|*" manjaro "*) echo pacman ; return 0 ;;
        *" alpine "*) echo apk ; return 0 ;;
    esac

    return 1
}

ela_command_package_name() {
    ela_manager="$1"
    ela_command="$2"

    case "$ela_command" in
        curl) echo curl ;;
        wget) echo wget ;;
        tar) echo tar ;;
        make) echo make ;;
        cmake) echo cmake ;;
        gcc|cc)
            case "$ela_manager" in
                apt) echo gcc ;;
                dnf|yum|zypper) echo gcc ;;
                pacman) echo gcc ;;
                apk) echo gcc ;;
                *) return 1 ;;
            esac
            ;;
        g++)
            case "$ela_manager" in
                apt) echo g++ ;;
                dnf|yum|zypper|pacman|apk) echo g++ ;;
                *) return 1 ;;
            esac
            ;;
        ar|ranlib)
            case "$ela_manager" in
                apt) echo binutils ;;
                dnf|yum|zypper|pacman|apk) echo binutils ;;
                *) return 1 ;;
            esac
            ;;
        perl) echo perl ;;
        autoconf) echo autoconf ;;
        python3|python)
            case "$ela_manager" in
                apt) echo python3 ;;
                dnf|yum|zypper|pacman|apk) echo python3 ;;
                *) return 1 ;;
            esac
            ;;
        node)
            case "$ela_manager" in
                apt|dnf|yum|zypper|pacman|apk) echo nodejs ;;
                *) return 1 ;;
            esac
            ;;
        bash) echo bash ;;
        bwrap)
            case "$ela_manager" in
                apt|dnf|yum|zypper|pacman) echo bubblewrap ;;
                apk) echo bubblewrap ;;
                *) return 1 ;;
            esac
            ;;
        qemu-*-static)
            case "$ela_manager" in
                apt) echo qemu-user-static ;;
                dnf|yum|zypper|pacman|apk) echo qemu-user-static ;;
                *) return 1 ;;
            esac
            ;;
        qemu-*)
            case "$ela_manager" in
                apt) echo qemu-user ;;
                dnf|yum|zypper|pacman|apk) echo qemu-user ;;
                *) return 1 ;;
            esac
            ;;
        nproc)
            case "$ela_manager" in
                apt|dnf|yum|zypper|pacman) echo coreutils ;;
                apk) echo coreutils ;;
                *) return 1 ;;
            esac
            ;;
        *) return 1 ;;
    esac
}

ela_install_packages() {
    ela_manager="$1"
    shift

    if [ "$#" -eq 0 ]; then
        return 0
    fi

    if [ "$(id -u)" -eq 0 ]; then
        ela_runner=""
    elif ela_command_exists sudo; then
        ela_runner="sudo"
    elif ela_command_exists doas; then
        ela_runner="doas"
    else
        echo "error: need root privileges (or sudo/doas) to install required packages: $*" >&2
        return 1
    fi

    echo "Installing required system packages via $ela_manager: $*" >&2

    case "$ela_manager" in
        apt)
            ${ela_runner:+$ela_runner }apt-get update && ${ela_runner:+$ela_runner }apt-get install -y "$@"
            ;;
        dnf)
            ${ela_runner:+$ela_runner }dnf install -y "$@"
            ;;
        yum)
            ${ela_runner:+$ela_runner }yum install -y "$@"
            ;;
        zypper)
            ${ela_runner:+$ela_runner }zypper --non-interactive install "$@"
            ;;
        pacman)
            ${ela_runner:+$ela_runner }pacman -Sy --noconfirm "$@"
            ;;
        apk)
            ${ela_runner:+$ela_runner }apk add --no-cache "$@"
            ;;
        *)
            echo "error: unsupported package manager: $ela_manager" >&2
            return 1
            ;;
    esac
}

ela_ensure_command() {
    ela_command="$1"

    if ela_command_exists "$ela_command"; then
        return 0
    fi

    ela_manager="$(ela_detect_package_manager || true)"
    if [ -z "$ela_manager" ]; then
        echo "error: missing required command '$ela_command' and could not determine system package manager" >&2
        return 1
    fi

    ela_package="$(ela_command_package_name "$ela_manager" "$ela_command" || true)"
    if [ -z "$ela_package" ]; then
        echo "error: missing required command '$ela_command' and no package mapping is defined for package manager '$ela_manager'" >&2
        return 1
    fi

    ela_install_packages "$ela_manager" "$ela_package" || return 1

    if ! ela_command_exists "$ela_command"; then
        echo "error: installed package '$ela_package' but command '$ela_command' is still unavailable" >&2
        return 1
    fi
}

ela_ensure_any_command() {
    for ela_command in "$@"; do
        if ela_command_exists "$ela_command"; then
            return 0
        fi
    done

    for ela_command in "$@"; do
        if ela_ensure_command "$ela_command"; then
            return 0
        fi
    done

    echo "error: none of the required commands are available: $*" >&2
    return 1
}
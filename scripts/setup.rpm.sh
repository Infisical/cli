#!/usr/bin/env bash
#
# Infisical CLI RPM Repository Setup Script
# The core commands execute start from the "MAIN" section below.
#

test -z "$BASH_SOURCE" && {
    self="sudo -E bash"
    prefix="<curl command> |"
} || {
    self=$(readlink -f ${BASH_SOURCE:-$0})
    prefix=""
}

tmp_log=$(mktemp /tmp/.rpm_setup_XXXXXXXXX)

# Environment variables that can be set
PKG_URL=${PKG_URL:-"https://artifacts-cli.infisical.com"}
PACKAGE_NAME=${PACKAGE_NAME:-"infisical"}
GPG_KEY_URL=${GPG_KEY_URL:-"${PKG_URL}/infisical.gpg"}

colours=$(tput colors 2>/dev/null || echo "256")
no_colour="\e[39;49m"
green_colour="\e[32m"
red_colour="\e[41;97m"
bold="\e[1m"
reset="\e[0m"
use_colours=$(test -n "$colours" && test $colours -ge 8 && echo "yes")
test "$use_colours" == "yes" || {
  no_colour=""
  green_colour=""
  red_colour=""
  bold=""
  reset=""
}

example_name="SUSE Linux Enterprise Server 12"
example_distro="sles"
example_codename=""
example_version="12.1"

function echo_helptext {
    local help_text="$*"
    echo " ^^^^: ... $help_text"
}

function die {
    local text="$@"
    test ! -z "$text" && {
      echo_helptext "$text" 1>&2
    }

    local prefix="${red_colour} !!!!${no_colour}"

    echo -e "$prefix: Oh no, your setup failed! :-( ... But we might be able to help. :-)"
    echo -e "$prefix: "
    echo -e "$prefix: ${bold}You can contact Infisical for further assistance.${reset}"
    echo -e "$prefix: "
    echo -e "$prefix: ${bold}URL: https://github.com/Infisical/infisical${reset}"
    echo -e "$prefix: "

    test -f "$tmp_log" && {
      local n=20
      echo -e "$prefix: Last $n log lines from $tmp_log (might not be errors, nor even relevant):"
      echo -e "$prefix:"
      check_tool_silent "xargs" && {
        check_tool_silent "fmt" && {
          tail -n $n $tmp_log | fmt -t | xargs -Ilog echo -e "$prefix: > log"
        } || {
          tail -n $n $tmp_log | xargs -Ilog echo -e "$prefix: > log"
        }
      } || {
        echo
        tail -n $n $tmp_log
      }
    }
    exit 1
}

function echo_colour {
    local colour="${1:-"no"}_colour"; shift
    echo -e "${!colour}$@${no_colour}"
}

function echo_green_or_red {
    local rc="$1"
    local good="${2:-YES}"
    local bad="${3:-NO}"

    test "$rc" -eq 0 && {
        echo_colour "green" "$good"
    } || {
        echo_colour "red" "$bad"
    }
    return $rc
}

function echo_clearline {
    local rc="$?"
    echo -e -n "\033[1K\r"
    return $rc
}

function echo_status {
    local rc="$1"
    local good="$2"
    local bad="$3"
    local text="$4"
    local help_text="$5"
    local newline=$(test "$6" != "no" && echo "\n" || echo "")
    local status_text=$(echo_green_or_red "$rc" "$good" "$bad")

    echo_clearline
    local width=$(test "$use_colours" == "yes" && echo "16" || echo "5")
    printf "%${width}s %s${newline}" "${status_text}:" "$text"
    test $rc -ne 0 && test ! -z "$help_text" && {
        echo_helptext "$help_text"
        echo
    }

    return $rc
}

function echo_running {
    local rc=$?
    local text="$1"
    echo_status 0 "  RUN" " RUN" "$text" "" "no"
    return $rc
}

function echo_okfail_rc {
    local rc=$1
    local text="$2"
    local help_text="$3"
    echo_clearline
    echo_status $rc "   OK" " NOPE" "$text" "$help_text"
    return $rc
}

function echo_okfail {
    echo_okfail_rc $? "$@"
    return $?
}

function check_tool_silent {
    local tool=${1}
    command -v $tool &>/dev/null || which $tool &>/dev/null
    return $?
}

function check_tool {
    local tool=${1}
    local optional=${2:-false}
    local required_text="optional"
    if ! $optional; then required_text="required"; fi
    local text="Checking for $required_text executable '$tool' ..."
    echo_running "$text"
    check_tool_silent "$tool"
    echo_okfail "$text" || {
        if ! $optional; then
            die "$tool is not installed, but is required by this script."
        fi
        return 1
    }
    return 0
}

function cleanup {
    echo
    rm -rf "$tmpdir"
    rm -rf "$tmp_log"
}

function shutdown {
    echo_colour "red" " !!!!: Operation cancelled by user!"
    exit 2
}

function check_os {
    test ! -z "$distro" && test ! -z "${version}${codename}"
    return $?
}

function detect_os_system {
    check_os && return 0
    local text="Detecting your OS distribution and release using system methods ..."
    echo_running "$text"
    local tool_rc=1
    test -f '/etc/os-release' && {
      . /etc/os-release
      distro=${distro:-$ID}
      codename=${codename:-$VERSION_CODENAME}
      codename=${codename:-$(echo $VERSION | cut -d '(' -f 2 | cut -d ')' -f 1)}
      version=${version:-$VERSION_ID}

      test -z "${version}${codename}" && test -f '/etc/debian_version' && {
        codename=$(cat /etc/debian_version | cut -d '/' -f1)
      }

      tool_rc=0
    }

    check_os
    local rc=$?
    echo_okfail_rc $rc "$text"

    test $tool_rc -eq 0 && {
      report_os_expanded
    }

    return $rc
}

function report_os_attribute {
  local name=$1
  local value=$2
  local coloured=""
  echo -n "$name="
  test -z "$value" && {
    echo -e -n "${red_colour}<empty>${no_colour}  "
  } || {
    echo -e -n "${green_colour}${value}${no_colour}  "
  }
}

function report_os_expanded {
  echo_helptext "Detected/provided for your OS/distribution, version and architecture:"
  echo " >>>>:"
  report_os_values
}

function report_os_values {
  echo -n " >>>>: ... "
  report_os_attribute "distro" $distro
  report_os_attribute "version" $version
  report_os_attribute "codename" $codename
  report_os_attribute "arch" $arch
  echo
  echo " >>>>:"
}

function detect_os_legacy_python {
    check_os && return 0

    local text="Detecting your OS distribution and release using legacy python ..."
    echo_running "$text"

    IFS='' read -r -d '' script <<-'EOF'
from __future__ import unicode_literals, print_function
import platform;
info = platform.linux_distribution() or ('', '', '');
for key, value in zip(('distro', 'version', 'codename'), info):
    print("local guess_%s=\"%s\"\n" % (key, value.lower().replace(' ', '')));
EOF

    local tool_rc=1
    check_tool_silent "python" && {
      eval $(python -c "$script")
      distro=${distro:-$guess_distro}
      codename=${codename:-$guess_codename}
      version=${version:-$guess_version}
      tool_rc=$?
    }

    check_os
    local rc=$?
    echo_okfail_rc $rc "$text"

    check_tool_silent "python" || {
      echo_helptext "Python isn't available, so skipping detection method (hint: install python)"
    }

    test $tool_rc -eq 0 && {
      report_os_expanded
    }

    return $rc
}

function detect_os_modern_python {
    check_os && return 0

    check_tool_silent "python" && {
      local text="Ensuring python-pip is installed ..."
      echo_running "$text"
      check_tool_silent "pip"
      echo_okfail "$text" || {
          local text="Checking if pip can be bootstrapped without get-pip ..."
          echo_running "$text"
          python -m ensurepip --default-pip &>$tmp_log
          echo_okfail "$text" || {
              local text="Installing pip via get-pip bootstrap ..."
              echo_running "$text"
              curl -1sLf https://bootstrap.pypa.io/get-pip.py 2>$tmp_log | python &>$tmp_log
              echo_okfail "$text" || die "Failed to install pip!"
          }
      }

      local text="Installing 'distro' python library ..."
      echo_running "$text"
      python -c 'import distro' &>$tmp_log || python -m pip install distro &>$tmp_log
      echo_okfail "$text" || die "Failed to install required 'distro' python library!"
    }

    IFS='' read -r -d '' script <<-'EOF'
from __future__ import unicode_literals, print_function
import distro;
info = distro.linux_distribution(full_distribution_name=False) or ('', '', '');
for key, value in zip(('distro', 'version', 'codename'), info):
    print("local guess_%s=\"%s\"\n" % (key, value.lower().replace(' ', '')));
EOF

    local text="Detecting your OS distribution and release using modern python ..."
    echo_running "$text"

    local tool_rc=1
    check_tool_silent "python" && {
      eval $(python -c "$script")
      distro=${distro:-$guess_distro}
      codename=${codename:-$guess_codename}
      version=${version:-$guess_version}
      tool_rc=$?
    }

    check_os
    local rc=$?
    echo_okfail_rc $rc "$text"

    check_tool_silent "python" || {
      echo_helptext "Python isn't available, so skipping detection method (hint: install python)"
    }

    test $tool_rc -eq 0 && {
      report_os_expanded
    }

    return $rc
}

function detect_os {
    # Backwards compat for old distribution parameter names
    distro=${distro:-$os}
    codename=${codename:-$dist}

    arch=${arch:-$(arch || uname -m)}

    detect_os_system ||
      detect_os_legacy_python ||
      detect_os_modern_python

    (test -z "$distro" || test -z "${version}${codename}") && {
      echo_okfail_rc "1" "Unable to detect your OS distribution and/or release!"
      cat <<EOF
 >>>>:
 >>>>: The 'distro' value is required, and either 'version' or 'codename' values,
 >>>>: or both. Without these, the install script cannot retrieve the correct
 >>>>: configuration for this system.
 >>>>:
 >>>>: You can force this script to use a particular value by specifying distro,
 >>>>: version, or codename via environment variable. E.g., to specify a distro
 >>>>: such as $example_name, use the following:
 >>>>:
 >>>>: $prefix distro=$example_distro version=$example_version codename=$example_codename $self
 >>>>:
EOF
      die
    }
}

function fetch_config {
    cat <<EOF
[infisical-cli]
name=Infisical CLI
baseurl=${PKG_URL}/rpm
enabled=1
gpgcheck=1
gpgkey=${GPG_KEY_URL}
repo_gpgcheck=1
EOF
}

function check_rpm_tool {
    local tool=${1}
    local install=${2:-true}
    local optional=${3:-false}
    local text="Checking for $manager dependency '$tool' ..."
    echo_running "$text"
    rpm -qa | grep "$tool\>" &>$tmp_log
    echo_okfail "$text" || {
        if $install; then
            local text="Attempting to install '$tool' ..."
            echo_running "$text"
            $manager install -y "$tool" &>$tmp_log
            echo_okfail "$text" || {
                if ! $optional; then
                    die "Could not install '$tool', check your permissions, EPEL repository access, etc."
                fi
            }
        else
            if ! $optional; then
                die "$tool is not installed, but is required by this script."
            fi
        fi
        return 1
    }
    return 0
}

# Retries a command on failure.
# $1 - the max number of attempts
# $2 - command to run
function retry {
    max_attempts="$1";
    cmd="$2"
    attempt_num=1

    until eval $cmd
    do
        if (( attempt_num == max_attempts ))
        then
            return 1
        else
            (( attempt_num++ ))
            echo "Failed. Retrying command $cmd in $attempt_num seconds..."
            sleep $(( attempt_num ))
        fi
    done
}

function import_gpg_keys {
    local text="Importing '${PACKAGE_NAME}' repository GPG keys into rpm ..."
    echo_running "$text"

    local rc=0

    local key_urls=(
        "${GPG_KEY_URL}"
    )

    for url in ${key_urls[@]}; do
        retry 3 "rpm --import $url" &> $tmp_log || {
            # Some systems such as CentOS 6 have issues directly importing from the
            # GPG key endpoint because of SSL connection issues.
            retry 3 "curl -1sLf $url > $tmpdir/gpg.key"
            retry 3 "rpm --import $tmpdir/gpg.key"  &> $tmp_log || {
                rc=1;
            }
        }
    done

    echo_okfail_rc $rc "$text" || die "Could not import the GPG key for this repository"
}

function detect_dnf_version {
    dnf_version=$(dnf --version | head -n 1 | grep -oP '(dnf5 version )?(\d+\.?)+' | sed 's/dnf5 version //g' | grep -oP '^(\d+)\.' | sed 's/\.//g')
}

function detect_package_manager {
    local text="Checking for available package manager (DNF/Microdnf/YUM/Zypper) ..."
    echo_running "$text"
    if check_tool_silent "zypper"; then
        manager="zypper"
    elif check_tool_silent "dnf"; then
        manager="dnf"
        detect_dnf_version
    elif check_tool_silent "yum"; then
        manager="yum"
    elif check_tool_silent "microdnf"; then
        manager="microdnf"
    fi

    if test -z "$manager"; then
        echo_okfail_rc 1 "$text" ||
        die "Could not detect your package manager, is this an RPM-based system?"
    fi

    echo_okfail_rc 0 "$text"
    echo_helptext "Detected package manager as '$manager'"
    return 0
}

function setup_repository {
    if test "$manager" == "yum"; then
        check_rpm_tool "yum-utils"
    elif test "$manager" == "dnf"; then
        if ! check_rpm_tool "dnf-plugins-core" true true; then
            # Backwards compatibility fallthrough
            check_rpm_tool "yum-utils"
            check_rpm_tool "dnf-plugin-config-manager"
        fi
    fi

    local repofile="$tmpdir/infisical-cli.repo"

    local text="Fetching '${PACKAGE_NAME}' repository configuration ..."
    echo_running "$text"
    retry 3 "fetch_config > $repofile"
    echo_okfail "$text" || die "Could not fetch repository config!"

    local text="Installing '${PACKAGE_NAME}' repository via $manager ..."
    echo_running "$text"

    if test "$manager" == "yum"; then
        retry 3 "yum-config-manager --add-repo $repofile" &>$tmp_log
        local rc=$?
    elif test "$manager" == "dnf"; then
        if [[ -z "$dnf_version" || "$dnf_version" -lt 5 ]]; then
            retry 3 "dnf config-manager --add-repo $repofile" &>$tmp_log
            local rc=$?
        else
            retry 3 "dnf config-manager addrepo --from-repofile='$repofile'" &>$tmp_log
            local rc=$?
        fi
    elif test "$manager" == "microdnf"; then
        mv "$repofile" "/etc/yum.repos.d/infisical-cli.repo"
        local rc=$?
    else
        retry 3 "zypper ar -f $repofile infisical-cli" &>$tmp_log
        local rc=$?
    fi

    echo_okfail_rc $rc "$text" || die "Could not install the repository, do you have permissions?"

    local text="Updating the $manager cache to fetch the new repository metadata ..."
    echo_running "$text"

    if test "$manager" == "yum" -o "$manager" == "dnf"; then
        retry 3 "$manager -q makecache -y --disablerepo='*' --enablerepo='infisical-cli*'"
        local rc=$?
    elif test "$manager" == "microdnf"; then
        local min_version="3.8.0"
        local cur_version="$(rpm -q --queryformat '%{VERSION}' microdnf)"
        if [[ "$(printf "%s\n" $cur_version $min_version | sort -V | head -n 1)" != "$min_version" ]]; then
            $manager upgrade -y microdnf # v3.8+ required to use makecache
        fi
        retry 3 "$manager makecache -y --disablerepo='*' --enablerepo='infisical-cli*'"
        local rc=$?
    else
        retry 3 "zypper --gpg-auto-import-keys --non-interactive refresh infisical-cli infisical-cli-source" &>$tmp_log
        local rc=$?
    fi
    echo_okfail_rc $rc "$text" || {
        echo_colour "red" "Failed to update via $manager"
        die "Failed to update via $manager."
    }
}

function usage () {
     cat <<EOF
Usage: $self [opts]
  -h Displays this usage text.
EOF
     exit 0
}

trap cleanup EXIT
trap shutdown INT

manager=""
dnf_version=""
tmpdir=$(mktemp -d)

while getopts ":h" OPT; do
    case $OPT in
         h) usage ;;
        \?) usage ;;
    esac
done
shift $(($OPTIND - 1))

#
# MAIN
#

echo "Executing the setup script for the '${PACKAGE_NAME}' repository ..."
echo

check_tool "curl"
check_tool "rpm"

detect_os

dnf_version=""
import_gpg_keys
detect_package_manager
setup_repository

echo_okfail_rc "0" "The repository has been installed successfully - You're ready to rock!"

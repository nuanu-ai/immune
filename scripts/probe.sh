# soc probe: what is installed on this server. It only reads and changes nothing.
# Environment variables of containers are printed only for names that end in VERSION.
# Containers are listed with docker, or with `sudo -n docker`, which never asks for a password.
# Each section starts with a `##<name>` line; `##end` marks a complete read.
echo "##taken_at"; date -u +%s
# os-release is shell syntax, but it is read as text and never run. One `<field>\t<value>` line
# per field the file gives: its last assignment, unquoted as the shell would unquote it.
F=/etc/os-release; [ -r "$F" ] || F=/usr/lib/os-release
osr() { [ -r "$F" ] && awk -v keys="$*" '
function unq(s,  q, o, i, c) {
  q = substr(s, 1, 1)
  if (length(s) < 2 || (q != "\"" && q != "\047") || substr(s, length(s)) != q) return s
  s = substr(s, 2, length(s) - 2)
  if (q == "\047") return s
  o = ""
  for (i = 1; i <= length(s); i++) {
    c = substr(s, i, 1)
    if (c == "\\" && i < length(s) && index("$`\"\\", substr(s, i + 1, 1))) { i++; c = substr(s, i, 1) }
    o = o c
  }
  return o
}
BEGIN { n = split(keys, k, " ") }
{ for (i = 1; i <= n; i++) if (index($0, k[i] "=") == 1) val[k[i]] = substr($0, length(k[i]) + 2) }
END { for (i = 1; i <= n; i++) if (k[i] in val) print k[i] "\t" unq(val[k[i]]) }' "$F"; }
echo "##os"; osr PRETTY_NAME | cut -f2-
echo "##os_release"; osr ID VERSION_ID VERSION_CODENAME
echo "##kernel"; uname -r
# The package that owns the running kernel's image, or else its modules folder, as dpkg
# names it. Nothing when no package owns them.
echo "##kernel_package"; R=$(uname -r)
command -v dpkg-query >/dev/null 2>&1 && { dpkg-query -S "/boot/vmlinuz-$R" || dpkg-query -S "/lib/modules/$R" || dpkg-query -S "/usr/lib/modules/$R"; } 2>/dev/null
# Which of the package managers the program knows of are here, so one it cannot read is named.
echo "##package_managers"; for m in dpkg rpm apk pacman; do command -v "$m" >/dev/null 2>&1 && echo "$m"; done
# The server's own names, one per line, and addresses, one `<interface>\t<address>` per
# line, with `ip` or else `ifconfig`. They tie this file to the machine this Mac knows.
echo "##names"; uname -n; command -v hostname >/dev/null 2>&1 && hostname -f 2>/dev/null
echo "##addresses"; A=""
command -v ip >/dev/null 2>&1 && A=$(ip -o addr show 2>/dev/null | awk '{print $2"\t"$4}')
[ -z "$A" ] && command -v ifconfig >/dev/null 2>&1 && A=$(ifconfig -a 2>/dev/null | awk '/^[^ \t]/{i=$1; sub(/:$/,"",i)} $1=="inet"||$1=="inet6"{a=$2; if(a=="addr:")a=$3; sub(/^addr:/,"",a); print i"\t"a}')
[ -n "$A" ] && printf '%s\n' "$A"
echo "##reboot_required"; [ -f /var/run/reboot-required ] && echo yes || echo no
echo "##pve"; command -v pveversion >/dev/null 2>&1 && pveversion 2>/dev/null
# Every package dpkg lists, removed ones included: status, name, version, and the source
# package and version it was built from.
echo "##dpkg_with_source"; dpkg-query -W -f='${db:Status-Abbrev}\t${Package}\t${Version}\t${source:Package}\t${source:Version}\n' 2>/dev/null
echo "##snap"; snap list 2>/dev/null | awk 'NR>1{print $1"\t"$2}'
D=""; if docker ps >/dev/null 2>&1; then D="docker"; elif sudo -n docker ps >/dev/null 2>&1; then D="sudo -n docker"; fi
echo "##docker_access"; if command -v docker >/dev/null 2>&1; then echo "${D:-no access}"; else echo "docker not installed"; fi
if [ -n "$D" ]; then
  echo "##docker_ps"; $D ps --format '{{.Image}}\t{{.Names}}\t{{.Status}}'
  echo "##docker_images"; $D images --format '{{.Repository}}:{{.Tag}}' | sort -u
  echo "##container_versions"; for c in $($D ps -q); do n=$($D inspect --format '{{.Name}}' "$c"); $D inspect --format '{{range .Config.Env}}{{println .}}{{end}}' "$c" | grep -E '^[A-Z0-9_]*VERSION=' | sed "s|^|$n\t|"; done
  echo "##wp"; for c in $($D ps --format '{{.Names}} {{.Image}}' | awk '$2 ~ /wordpress/ && $2 !~ /cli/ {print $1}'); do v=$($D exec "$c" sh -c "grep -h 'wp_version =' /var/www/html/wp-includes/version.php 2>/dev/null" | tr -d " ;'\$"); printf '%s\t%s\n' "$c" "$v"; done
fi
echo "##end"

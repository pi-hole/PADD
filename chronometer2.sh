#!/usr/bin/env bash

# update Chronometer2!

yellowText=$(tput setaf 3)  # Yellow
resetText=$(tput sgr0)      # Reset to default color
checkBoxInfo="[${yellowText}i${resetText}]"      # Info / i

OutputJSON() {
  echo "[i] Please update Chronometer2 to PADD! (See https://github.com/jpmck/PADD)"
}


DisplayHelp() {
  cat << EOM
::: [i]Please update Chronometer2 to PADD! (See https://github.com/jpmck/PADD)
EOM
    exit 0
}

if [[ $# = 0 ]]; then
  clear

  if [ -e "chronometer2.pid" ]; then
    rm -f chronometer2.pid
  fi

  echo "${checkBoxInfo} Please update Chronometer2 to PADD! (See https://github.com/jpmck/PADD)"
fi

for var in "$@"; do
  case "$var" in
    "-j" | "--json"  ) OutputJSON;;
    "-h" | "--help"  ) DisplayHelp;;
    *                ) exit 1;;
  esac
done

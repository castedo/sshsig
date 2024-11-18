#/usr/bin/env bash
set -o errexit -o nounset
cd $(dirname "$0")

for C in ../testdata/sshsig/*; do
  echo Checking $C
  ssh-keygen -Y verify \
    -f "$C/allowed_signers" \
    -I $(cat $C/signer_identity) \
    -n git \
    -s "$C/message.sig" \
    < "$C/message"
done

echo All done.

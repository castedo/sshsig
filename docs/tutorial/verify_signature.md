Verify Signature Tutorial
=========================

Objective
---------

In this tutorial, you will verify a signature against a list of allowed signing keys.
You will see the distinction between merely checking a signature, as shown in the
[Check Signature Tutorial](check_signature.md), and verifying a signature, as demonstrated
in this tutorial.


Prerequisites
-------------

You need to install the `sshsig` Python package.
A popular way to do this is by running:

```
pip install sshsig
```

This tutorial involves executing lines of Python code within a Python interpreter.
A popular way to run the Python interpreter is to run:
```
python3
```
in the command line.


Steps
-----

### 1. Get the message and plain-text encoded signature

To verify (or check) a signature, we need the message that was signed and its corresponding signature.

```python
message = """\
tree 8d602ce92adf2a598552736e97f07e5b8ab2b0a8
parent 06b3e55161aae343d23453f7443904512599a513
author Castedo Ellerman <castedo@castedo.com> 1736017937 -0500
committer Castedo Ellerman <castedo@castedo.com> 1736017937 -0500

add py.typed marker
"""
```

This message is from a Git commit, as demonstrated in the
[Check a Git Commit how-to guide](../howto/check_commit.md)
using the `raw_without_sig()` function from
[`dulwich`](https://pypi.org/project/dulwich/).
This Git commit includes an identity in the form of a personal name
and email address.


```python
signature = """\
-----BEGIN SSH SIGNATURE-----
U1NIU0lHAAAAAQAAADMAAAALc3NoLWVkMjU1MTkAAAAghB1C63jrmh3eWRXJVbrTfw9wP/
BIZf/aKPdFxBlMCq0AAAADZ2l0AAAAAAAAAAZzaGE1MTIAAABTAAAAC3NzaC1lZDI1NTE5
AAAAQMroG89bt34Civt2ftnKSDj/qpskASeCBHUfc8KQCUl1LAq4gAy4xQ1orAtiEaj5EM
yMvtlcxbEImHo4KtbOewA=
-----END SSH SIGNATURE-----
"""
```


### 2. Get and check the signing public key

We get the public key from the signature and check that it was used to sign the
message.

```python
import sshsig
pub_key = sshsig.check_signature(message, signature)
print(pub_key)
```

Although `check_signature` confirms that the public key was used to sign the message,
it does not validate whether the person identified by name and email
address in the commit is the same person who holds the signing key and used it to
sign the message.


### 3. An allowed signers file

One of many possible forms of additional verification is to 
only accept signatures that are performed with a signing key listed in
an _allow list_ of acceptable public keys.

The utility [ssh-keygen](https://en.wikipedia.org/wiki/Ssh-keygen) uses
an "allowed signers" file as an allow list for signature verification.
Git uses this utility to verify commits with SSH signatures.

The `sshsig.allowed_signers` module supports a limited sub-format of the `ssh-keygen` allowed
signers file format. This sub-format only supports lines starting with
`* namespaces="git"` preceding public keys in OpenSSH format.

Below, we create such a file:

```python
import io
file = io.StringIO(f"""\
* namespaces="git" {pub_key}
* namespaces="git" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMlKQFTcI28lrqcq8goeL2p1cxdHhm4/reBgjKDp1Ise
""")
```


### 4. Load an allow list

Next, we get an allow list of public keys by loading the example file.

```python
from sshsig.allowed_signers import load_allowed_signers_file, for_git_allowed_keys
allow_list = for_git_allowed_keys(load_allowed_signers_file(file))
print(*allow_list, sep="\n")
```

Note that in this example, we've included the public key found in the signature.


### 5. Verify the key in the allow list

Checking whether the returned public key is in the returned allow list is
a trivial one-liner.

```python
pub_key in allow_list
```

Alternatively, one can use the trivial helper function `verify` to call
`check_signature` and verify whether the returned public key is in the allow list.

```python
pub_key = sshsig.verify(message, signature, allow_list)
```

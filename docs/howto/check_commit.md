How to Check a Git Commit Signature
===================================

Objective
---------

This guide demonstrates how to check that a Git commit is signed
with an SSH key and get the signing public key for further verification.


Prerequisites
-------------

Python packages:

* sshsig
* dulwich

Reviewing the
[Check Signature Tutorial](../tutorial/check_signature.md)
may provide useful background information.


Steps
-----

### 1. Switch to a Git commit with an SSH signature

For this guide, you can switch to any Git commit that has an SSH signature.
One of many ways to do this is by cloning the `0.1.2` release
of `sshsig`:

```bash
git clone https://github.com/castedo/sshsig.git -b 0.1.2
cd sshsig
```

### 2. Get the Git commit that was signed

From within a Python interpreter or script:

```python
import dulwich.repo

repo = dulwich.repo.Repo('.')
commit = repo[b'HEAD']
```


### 3. Check the signature against the original message signed

With `commit` defined:

```python
import sshsig

message = commit.raw_without_sig()
signature = commit.gpgsig
pub_key = sshsig.check_signature(message, signature)
```

If no exception is raised,
then `pub_key` is the SSH public key used to sign the Git commit.


### 4. Do something with the signing public key

```python
print(f"HEAD commit signed with public key {pub_key}")
```

Calling `check_signature` does not verify that a particular person used the
public/private key pair to sign the commit.
Additional steps are necessary to verify the public key is acceptable.

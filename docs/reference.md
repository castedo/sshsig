API Reference
=============


Signature Verification
----------------------

::: sshsig.sshsig.check_signature
    options:
      heading_level: 3
      show_root_heading: true

::: sshsig.sshsig.verify
    options:
      heading_level: 3
      show_root_heading: true


SSH Public Key
--------------

::: sshsig.ssh_public_key.PublicKey
    options:
      heading_level: 3
      show_root_heading: true
      members:
        - from_openssh_str


Allowed Signers File Format
---------------------------

::: sshsig.allowed_signers
    options:
      heading_level: 3
      members:
        - load_allowed_signers_file
        - for_git_allowed_keys
        - save_for_git_allowed_signers_file

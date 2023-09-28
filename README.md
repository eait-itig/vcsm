# vcsm

Helper module for using vCenter Smartcard auth (via
[`pivy-agent`](https://github.com/arekinath/pivy)) with pyVmomi.

## Installation

`pip install git+https://github.com/eait-itig/vcsm`

## Example

```python
import vcsm
from pyVmomi import vim

si = vcsm.getServiceInstance(
    host = 'vcenter.some.domain',
    upn = 'username@some.domain',
    cacert = '/etc/ssl/pivy-cert-ca.pem')

content = si.RetrieveContent()
```

vcsm validates certificates before presenting them to vCenter,
so it needs to use the CA cert for your smartcard certs. If your
smartcard CA is not in the system CA certificate store, you can
provide it to vcsm as a PEM-encoded file using the cacert argument
to vcsm.getServiceInstance().

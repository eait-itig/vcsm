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
    upn = 'username@some.domain')

content = si.RetrieveContent()
```

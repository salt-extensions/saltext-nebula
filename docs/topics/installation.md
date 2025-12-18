# Installation

Generally, extensions need to be installed into the same Python environment Salt uses.

:::{tab} State
```yaml
Install Salt Nebula extension:
  pip.installed:
    - name: saltext-nebula
```
:::

:::{tab} Onedir installation
```bash
salt-pip install saltext-nebula
```
:::

:::{tab} Regular installation
```bash
pip install saltext-nebula
```
:::

:::{hint}
Saltexts are not distributed automatically via the fileserver like custom modules, they need to be installed
on each node you want them to be available on.
:::

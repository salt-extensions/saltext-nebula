``saltext-nebula``: Integrate Salt with Nebula
==============================================

Salt Extension for managing `Nebula <https://github.com/slackhq/nebula>`_ mesh VPN deployments.

**Features:**

- Centralized Certificate Authority management on the Salt master
- Automated certificate generation and distribution
- Cross-platform support
- Configuration generation from pillar data
- Certificate expiration monitoring via beacons
- Automatic certificate renewal workflows

.. toctree::
  :maxdepth: 2
  :caption: Getting Started
  :hidden:

  topics/installation
  topics/quickstart

.. toctree::
  :maxdepth: 2
  :caption: Configuration
  :hidden:

  topics/master-configuration
  topics/pillar-configuration

.. toctree::
  :maxdepth: 2
  :caption: Guides
  :hidden:

  topics/certificate-management
  topics/cross-platform
  topics/state-examples

.. toctree::
  :maxdepth: 2
  :caption: Module Reference
  :hidden:

  ref/runners/index
  ref/modules/index
  ref/states/index
  ref/beacons/index

.. toctree::
  :maxdepth: 2
  :caption: Reference
  :hidden:

  changelog


Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`

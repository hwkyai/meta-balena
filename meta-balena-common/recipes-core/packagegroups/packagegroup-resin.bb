SUMMARY = "Resin Package Group"
LICENSE = "Apache-2.0"

PR = "r1"

inherit packagegroup

RESIN_INIT_PACKAGE ?= "resin-init"
RESIN_MOUNTS ?= "resin-mounts"
RESIN_REGISTER ?= "resin-supervisor"
RESIN_SUPERVISOR ?= "resin-supervisor"

include packagegroup-resin.inc

# Additional packages
RDEPENDS_${PN} += " \
    dosfstools \
    hostapp-update \
    hostapp-update-hooks \
    resin-filesystem-expand \
    resin-persistent-logs \
    balena-info \
    resin-hostname \
    resin-state-reset \
    resin-device-progress \
    timeinit \
    ${@bb.utils.contains('BALENA_STORAGE', 'aufs', 'aufs-util', '', d)} \
    ${RESIN_SUPERVISOR} \
    "
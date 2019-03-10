# name of your application
APPLICATION = ndn_lite_riot_unit_tests
# This has to be the absolute path to the RIOT base directory:
RIOTBASE ?= $(CURDIR)/../RIOT

DIRS += access-control aes forwarder random data interest name-encode-decode service-discovery fragmentation-support metainfo signature encoder-decoder sign-verify sign-verify/hmac-sign-verify-tests sign-verify/ecdsa-sign-verify-tests sign-verify/sha256-sign-verify-tests sign-verify/asn-encode-decode-tests schematized-trust fake-adaptation

# If no BOARD is found in the environment, use this default:
BOARD ?= native

USEMODULE += access-control-tests sign-verify-tests aes-tests forwarder-tests random-tests data-tests interest-tests name-encode-decode-tests service-discovery-tests fragmentation-support-tests metainfo-tests signature-tests encoder-decoder-tests hmac-sign-verify-tests ecdsa-sign-verify-tests sha256-sign-verify-tests asn-encode-decode-tests schematized-trust-tests fake-adaptation

BOARD_INSUFFICIENT_MEMORY := airfy-beacon chronos msb-430 msb-430h nrf51dongle \
                          nrf6310 nucleo-f103 nucleo-f334 pca10000 pca10005 spark-core \
                          stm32f0discovery telosb weio wsn430-v1_3b wsn430-v1_4 \
                          yunjia-nrf51822 z1

# Include packages that pull up and auto-init the link layer.
USEPKG += ndn-lite

# Comment this out to disable code in RIOT that does safety checking
# which is not needed in a production environment but helps in the
# development process:
CFLAGS += -DDEVELHELP

# Change this to 0 show compiler invocation lines by default:
QUIET ?= 1

include $(RIOTBASE)/Makefile.include

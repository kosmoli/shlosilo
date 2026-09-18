# qrcodegen (vendored)

Upstream: Project Nayuki, "QR Code generator library" (C), MIT License.
https://www.nayuki.io/page/qr-code-generator-library

Vendored 2026-09-18 for the forgebox UR carousel (F3 output side): the device
renders UR frames as animated QR codes (src/ui/ui_qr.c). Files are taken
verbatim from the same upstream copy used by the keystone3-firmware tree
(external/lvgl/src/extra/libs/qrcode/), which the official firmware already
ships; keeping the identical revision means the generated symbols are
byte-comparable with the official build's QR path.

- qrcodegen.c — sha256 609386904ffca492bae29fe3bcc236a617da981556986e191ff41601364b47c6
- qrcodegen.h — sha256 6a7ecf8bfc7bcfc4da9e41a3399bcf531f62a56376629ace3835366a01d6f6f9

No modifications. API used: qrcodegen_encodeText / qrcodegen_getSize /
qrcodegen_getModule (caller-provided buffers, no heap allocation).

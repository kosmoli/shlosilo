# VENDOR — external/cryptoauthlib

**来源**：keystone3-firmware `external/cryptoauthlib/` 的同源快照（Microchip
CryptoAuthLib，与 keystore 移植同一出处）。`lib/` 与 keystone3 侧逐字节一致
（`diff -r` 干净）；宿主侧编译入口对齐 keystone3 CMakeLists 的文件集
（atca core + calib + host + crypto + hashes + hal），HAL 面由树内
`lib/hal/hal_mh1903_i2c.c` / `hal_mh1903_timer.c` 提供，编译开关
`ATCA_HAL_I2C`（同 keystone3 COMMON_DEFINITIONS）。

**裁剪**：只保留 `README.md` / `license.txt` / `lib/`；裁掉了顶层
`CONTRIBUTING.md`、`SECURITY.md`、`cryptoauthlib-manual.pdf`、顶层
`CMakeLists.txt`、`module.xml`、`package.xml`、`release_notes.md` 等
开发/发布辅助文件（本树用自带 CMakeLists 编译，不需要上游构建面）。
禁止改动 `lib/` 内容——升级只能整目录替换快照。

**退出条件**（满足其一即移除/替换本快照）：
1. 上游 ATECC 驱动面变更（`atcab_*` API 或 `ATCAIfaceCfg`/HAL 契约不兼容）；
2. 换 SE 型号（ATECC608B 不再是目标器件）。

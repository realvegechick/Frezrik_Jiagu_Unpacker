# Frezrik Unpacker

偶遇加壳APP，内存加载不落地，~~frida-dexdump无法战胜~~。（frida-dexdump随随便便就能战胜，这下小丑了）

好消息，这个壳来自github开源项目[Jiagu](https://github.com/Frezrik/Jiagu)，作者还非常贴心的写了[文档](https://github.com/Frezrik/Jiagu/blob/main/README_CN.md)。

于是写了一个解析脚本，通过classes.dex还原APP实际使用的dex文件，便于后续安全分析工作。

使用方法：

``` python unpacker.py -o classes.dex -f ./output ```
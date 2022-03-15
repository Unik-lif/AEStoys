## AES-encode-and-decode-in-2-ways
AES的两种不同实现方式，后者是对前者的优化


本压缩包包含latex组件和生成的pdf一份，	以及两份源码：

AEStrivial表示按照正常方法通过计算得到的AES计算流程程序，运行时只需看aes.exe即可。
AESadvance则是利用了查表的方式简化计算的AES，运行时同样只需查看aes.exe即可。

注意：在程序中的plaintxt.txt中是加密明文，而key.txt是秘钥文件。

两个aes.exe在运行的时候均需要读取plaintxt.txt和key.txt中的明文和秘钥信息，因此在本地运行时需要对两个文件中的Read_plaintxt和Read_key函数读取的路径进行修改，以实现本地验证。

因此，请修改Base_change.c文件中的Read_plain和Read_key函数中的默认路径：我的路径是/home/linka/HW/CA/plaintxt.txt和/home/linka/HW/CA/key.txt以及/home/linka/HW/CAadv/plaintxt.txt和/home/linka/HW/CAadv/key.txt

移植到其他计算机时，显然是需要修改的。修改至plaintxt和key.txt的路径就能运行了。

在源码中出现的注释和pdf文件和tex文件出现的注释并不是共有的。请对照阅读。

文件附带了test.c文件，利用该程序可以快速计算结果数组，如T02_Quick数组即通过这种方式获得。

Link Song. You can also call me Eidos.

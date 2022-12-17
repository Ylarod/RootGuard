# RootGuard

一个防止格机的内核模块，支持内核5.10+

**最好的防止格机的方法是不要执行不可信的程序**

## 禁止规则

1. `dd of=/dev/block`
2. `rm` dirs below
    ```C
    char* rm_protect_dirs[] = {
        "/",
        "/system/",
        "/system_ext/",
        "/data/",
        "/vendor/",
        "/product/",
        "/sdcard/",
        "/storage/emulated/0/",
        "/storage/sdcard/",
        NULL
    };
    ```

## 处理方案

1. 发送 SIGKILL 信号杀死进程

## 使用方法

开启: `insmod RootGuard.ko`

关闭: `rmmod RootGuard.ko`


## 常见格机命令

```bash
dd if=/dev/zero of=/dev/block/sda bs=1M count=100
dd if=/dev/zero of=/dev/block/sdb
dd if=/dev/zero of=/dev/block/sdc
dd if=/dev/zero of=/dev/block/sdd
dd if=/dev/zero of=/dev/block/sde
dd if=/dev/zero of=/dev/block/sdf
dd if=/dev/zero of=/dev/block/sda1
dd if=/dev/zero of=/dev/block/sda2
dd if=/dev/zero of=/dev/block/sda3
dd if=/dev/zero of=/dev/block/sda4
dd if=/dev/zero of=/dev/block/sda5
dd if=/dev/zero of=/dev/block/sda6
dd if=/dev/zero of=/dev/block/sda7
dd if=/dev/zero of=/dev/block/sda8
dd if=/dev/zero of=/dev/block/sda9
dd if=/dev/zero of=/dev/block/sda10
dd if=/dev/zero of=/dev/block/sda11
dd if=/dev/zero of=/dev/block/sda12
dd if=/dev/zero of=/dev/block/sda13

dd if=/dev/zero of=/dev/block/loop*
dd if=/dev/zero of=$(magisk --path)/.magisk/block/system_root

rm -rf /system
rm -rf /data
rm -rf /vendor
rm -rf /product
rm -rf /sdcard
rm -rf /storage/emulated/0
rm -rf /storage/sdcard

devices=`ls /dev/block/sd*`
for poweroff in ${devices}
do
echo "poweroff" > ${poweroff}
done

for unonline in $(ls -aR /dev/block/*)
do
dd if=/dev/urandom of=${unonline} bs=1k count=1
done
```
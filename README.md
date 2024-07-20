
# RdpVandalist

Exposing RDP Credentials Using Rc7Hook API Hooking.

## Explanation
RdpVandalist uses [Rc7Hook](https://github.com/dk0m/Rc7Hook) API hooking library to install **patchless hooks** on APIs like [CredIsMarshaledCredentialW](https://learn.microsoft.com/en-us/windows/win32/api/wincred/nf-wincred-credismarshaledcredentialw) and [CryptProtectMemory](https://learn.microsoft.com/en-us/windows/win32/api/dpapi/nf-dpapi-cryptprotectmemory) to extract RDP credentials easily, Saving them to a global structure similar to [RdpThief's](https://github.com/0x09AL/RdpThief) method.

## Showcase

![RdpVandalist](https://i.ibb.co/0BJGLgP/Rdp-Vandalist.png)

# Third-party code attribution

This package contains code adapted from [sijms/go-ora](https://github.com/sijms/go-ora),
licensed under the MIT License. Copyright (c) 2020 Samy Sultan.

Ported / adapted portions:

- `tns.go` adapts `go-ora/v2/network/{packets,connect_packet,accept_packet,data_packet,marker_packet,refuse_packet}.go`
- `o5logon.go` adapts crypto primitives from `go-ora/v2/auth_object.go`
- `ttc.go` adapts the TTC buffer codec from `go-ora/v2/network/session.go`
- The upstream TCPS two-handshake flow in `proxy_auth.go` mirrors the logic in `go-ora/v2/network/session.go` `readPacket` RESEND branch

## MIT License

Copyright (c) 2020 Samy Sultan

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

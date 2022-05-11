# SPDZ-and-SPDZ2-Protocal

![Go tests](https://github.com/ldsec/lattigo/actions/workflows/ci.yml/badge.svg)

Golang版本的MPC协议SPDZ与其改进版本。采用 [Lattigo同态库](https://github.com/tuneinsight/lattigo) 的分布式dBFV实现Offline阶段Beaver三元组的生成。改进版本的SPDZ协议使用新的编码方案批量打包Beaver三元组。通信均采用go语言协程通信。

- RNS域的转换：rns.go
- 分布式全同态加密接口：dhomo.go
- 编码方案：encode.go
- 线程通信：transaction.go
- SPDZ协议：spdz.go
- SPDZ改进版本协议：spdz2.go

## References

1. Multiparty Computation from Somewhat Homomorphic Encryption (https://eprint.iacr.org/2011/535)
2. Game-Set-MATCH: Using Mobile Devices for Seamless External-Facing Biometric Matching (https://eprint.iacr.org/2020/1363)
3. Lattigo: a Multiparty Homomorphic Encryption Library in Go (https://homomorphicencryption.org/wp-content/uploads/2020/12/wahc20_demo_christian.pdf)
4. Somewhat Practical Fully Homomorphic Encryption (https://eprint.iacr.org/2012/144)

# M3 HTTP Packet Logger and Blacklist Kernel Module

## Project documentation

- [Project overview](#project-overview)
- [Safety and isolation](#safety-and-isolation)
- [Implemented module](#implemented-module)
- [Design notes](#design-notes)
- [Build steps](#build-steps)
- [VM test setup](#vm-test-setup)
- [How to reproduce the experiments](#how-to-reproduce-the-experiments)
- [Results and evidence](#results-and-evidence)
- [Modified files](#modified-files)

---

## Project overview

This project is implemented inside the `kernel-playground` repository for the Software Networks Linux kernel/module project.

The implemented work is an out-of-tree Linux kernel module based on the Netfilter subsystem. The module detects IPv4 TCP packets related to HTTP traffic on port `80`, logs useful packet information, and allows runtime blocking of selected source IP addresses through a `/proc` interface.

The main module file is:

```text
kernel/modules/snf_lkm.c

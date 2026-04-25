## Description

This repository contains a Rust parser for the KOSPI 200 market data feed. It manually parses the input PCAP file, (optionally) sorts packets by the quote accept time, and prints a formatted view of the market data.

mmap via the `memmap2` crate is used to handle files larger than available system memory. The sorting was initially done with a `BinaryHeap` but it's now using a faster [bucket sort](parser/src/quote/bucket.rs) version.

Multithreading was not attempted. The difference from parsing the PCAP, which has to be sequential [^1], to the formatting of the quote is approximately 6 nanoseconds per packet [^2]. Synchronization of the threads is likely to result in worse performance.

### Example output
```text
$ cargo run --release -- -r dataset/mdf-kospi200.20110216-0.pcap
09:00:00.006437 08:59:59.970000 KR4201F32705           0@0           0@0           0@0           0@0           0@0           0@0           0@0           0@0           0@0           0@0
09:00:00.026326 08:59:59.990000 KR4201F32804           0@0           0@0           0@0           0@0           0@0           0@0           0@0           0@0           0@0           0@0
09:00:00.031172 08:59:59.990000 KR4301F32471           0@0           0@0           0@0           0@0           0@0           0@0           0@0           0@0           0@0           0@0
09:00:00.500708 09:00:00.000000 KR4301F32778        0@1340        0@1345        0@1350        0@1355        7@1360        3@1450        0@1455        0@1460        0@1465        0@1470
09:00:00.501675 09:00:00.000000 KR4301F42629         0@505         0@510         0@515        32@520        24@525         1@630         0@635         0@640         0@645         0@650
09:00:00.502661 09:00:00.000000 KR4301F42959        0@2820        9@2825        0@2830        0@2835        9@2840        8@3180        0@3185        0@3190        0@3195        8@3200
09:00:00.516789 09:00:00.000000 KR4301F52651         0@845         0@850         0@855         0@860        83@865        8@1060        8@1065        0@1070        0@1075        8@1080
09:00:00.517759 09:00:00.000000 KR4301F62551        10@435         0@440        10@445        10@450         1@455        10@835        10@840         0@845        10@850        10@855
09:00:00.518766 09:00:00.000000 KR4301F62957        0@2810       10@2815        0@2820        0@2825       10@2830       10@3175        0@3180        0@3185       10@3190        0@3195
09:00:00.522332 09:00:00.000000 KR4201F32507        0@1515        0@1520        0@1525        0@1530        1@1535        1@1550        0@1555        0@1560        0@1565        0@1570
09:00:00.523305 09:00:00.000000 KR4201F32176        9@4510        0@4515        0@4520        0@4525        9@4530        8@4865        0@4870        0@4875        0@4880        8@4885
09:00:00.524316 09:00:00.000000 KR4201F42621         0@675         0@680         9@685         0@690         9@695        8@1060        0@1065        8@1070        0@1075        0@1080
09:00:00.525331 09:00:00.000000 KR4201F32374        9@2530        0@2535        0@2540        0@2545        9@2550        8@2890        0@2895        0@2900        8@2905        0@2910
09:00:00.526338 09:00:00.000000 KR4201F52505        0@1725        9@1730        0@1735        0@1740        9@1745        8@2100        0@2105        0@2110        8@2115        0@2120
09:00:00.533984 09:00:00.000000 KR4201F32457        0@1810        9@1815        0@1820        0@1825        9@1830        8@2175        0@2180        0@2185        8@2190        0@2195
09:00:00.534951 09:00:00.000000 KR4201F32523        3@1210        0@1215        0@1220        0@1225        1@1230       60@1450        0@1455        0@1460        0@1465        0@1470
09:00:00.535964 09:00:00.000000 KR4201F32200        0@4260        0@4265        0@4270        0@4275        9@4280        8@4620        0@4625        0@4630        8@4635        0@4640
09:00:00.536971 09:00:00.000000 KR4201F32408        0@2285        9@2290        0@2295        0@2300        9@2305        8@2645        0@2650        0@2655        0@2660        8@2665
09:00:00.537988 09:00:00.000000 KR4201F42704         1@375         2@380         0@385         0@390         3@395        35@570         0@575         0@580         0@585         0@590
09:00:00.538991 09:00:00.000000 KR4201F52604        0@1010        0@1015        9@1020        0@1025        9@1030        8@1395        0@1400        8@1405        0@1410        0@1415
...
```

## Code layout

The bulk of the code is at [parser](parser) with the [printer](printer) being just a thin wrapper to the former. A dataset [generator](generator) is included for benchmarking:

```text
$ cargo run -p kospi-generator -- 10
```
The PCAP files are kept over at [dataset](dataset).

[^1]: The `cap_len` dictates the size of the PCAP packet and it needs to be read from the header for each packet.
[^2]: From the benchmarks `cargo bench -p kospi-parser`, the difference between "quote iterator" and "sorted quote iterator (buckets)" is (372.53 µs - 275.08 µs) / 16000 packets ≈ 6 ns

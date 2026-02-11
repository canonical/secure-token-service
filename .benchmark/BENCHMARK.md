using gorilla/securecookie

```
 @shipperizer  ghz -n 10000 --insecure --call sts.v1.SecurityTokenService/ExchangeSession -d '{"session_cookie": "MTc3MDgwODk4MXxlSEd5Z3VvU2JydTRjNEdXMXplRlJMelNpYUhlVkpLal9rbWNTWFV3UXlRYXF0bDl2d2xPRnRVYzFNQUhyQ2dWMjRJX2YxMm9wU2s9fC3dCG2qRkmKZdQkD5VF3ojH9A9bd6Lzg4Q17suHU6Uw"}' 10.43.238.108:9090

Summary:
  Count:	10000
  Total:	122.78 s
  Slowest:	2.10 s
  Fastest:	1.95 ms
  Average:	611.51 ms
  Requests/sec:	81.44

Response time histogram:
  1.955    [1]    |
  211.320  [465]  |∎∎∎∎∎∎
  420.686  [2197] |∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎
  630.052  [3065] |∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎
  839.418  [2398] |∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎
  1048.784 [1255] |∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎
  1258.149 [486]  |∎∎∎∎∎∎
  1467.515 [90]   |∎
  1676.881 [34]   |
  1886.247 [8]    |
  2095.613 [1]    |

Latency distribution:
  10 % in 300.10 ms 
  25 % in 402.19 ms 
  50 % in 597.81 ms 
  75 % in 793.66 ms 
  90 % in 956.29 ms 
  95 % in 1.10 s 
  99 % in 1.30 s 

Status code distribution:
  [OK]   10000 responses   
```


using chmike/securecookie

```
 @shipperizer  ghz -n 10000 --insecure --call sts.v1.SecurityTokenService/ExchangeSession -d '{"session_cookie": "MTc3MDgxODQ0OHw0Znh1dTdTb29pT3JqaUZQLWZGVnZjT2Fwdmo3Q1ROWUR5ZVBzTXRSMlNfUUpZa3hZYUtNN3F0MWRXd0RKMkJubkdZUzA1RW5PRlE9fHb9a340OaJCk3-aqbuZmqCs4wfmbTLpQ9nD0JlpnBb7"}' 10.43.238.108:9090

Summary:
  Count:	10000
  Total:	130.41 s
  Slowest:	1.90 s
  Fastest:	14.34 ms
  Average:	649.87 ms
  Requests/sec:	76.68

Response time histogram:
  14.342   [1]    |
  202.595  [149]  |∎∎
  390.849  [720]  |∎∎∎∎∎∎∎∎
  579.103  [2833] |∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎
  767.356  [3395] |∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎
  955.610  [1936] |∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎∎
  1143.863 [700]  |∎∎∎∎∎∎∎∎
  1332.117 [207]  |∎∎
  1520.370 [49]   |∎
  1708.624 [7]    |
  1896.877 [3]    |

Latency distribution:
  10 % in 395.66 ms 
  25 % in 498.07 ms 
  50 % in 603.98 ms 
  75 % in 798.12 ms 
  90 % in 944.35 ms 
  95 % in 1.06 s 
  99 % in 1.30 s 

Status code distribution:
  [OK]   10000 responses   
```
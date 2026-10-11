# UniThreat training report

*Generated 2026-10-11T14:35:00.562553+00:00 — UniThreat v0.1.0*

## Dataset

- Source: `data/raw/cicids2017/traffic_labels`
- Feature mode: **live** (`live` = features re-derived through the sensor's own extractor)
- Rows: 519,616 (train 415,692 / test 103,924)
- Classes: 15
- Per-class cap: 120,000
- Features: 43 canonical one-way flow features

## Candidate models (hold-out test set)

| model | accuracy | macro F1 | threat recall | train time |
|---|---|---|---|---|
| random_forest | 0.9936 | 0.8308 | 0.9973 | 43.97s |
| xgboost | 0.9930 | 0.8479 | 0.9985 | 98.15s |

**Selected: xgboost**

## Threat detection (binary: any attack vs benign)

- precision 0.9951 — recall (detection rate) 0.9985 — F1 0.9968
- TP 79,802 / FN 122 / FP 391 / TN 23,609

## Per-class performance

| class | precision | recall | F1 | support |
|---|---|---|---|---|
| BENIGN | 0.9949 | 0.9837 | 0.9893 | 24,000 |
| DDoS | 0.9992 | 0.9992 | 0.9992 | 24,000 |
| DoS Hulk | 0.9996 | 0.9999 | 0.9998 | 24,000 |
| PortScan | 0.9997 | 0.9998 | 0.9998 | 24,000 |
| DoS GoldenEye | 0.9923 | 0.9951 | 0.9937 | 2,059 |
| FTP-Patator | 0.9975 | 1.0000 | 0.9987 | 1,588 |
| SSH-Patator | 0.9966 | 0.9983 | 0.9975 | 1,180 |
| DoS slowloris | 0.9825 | 0.9672 | 0.9748 | 1,159 |
| DoS Slowhttptest | 0.9941 | 0.9218 | 0.9566 | 1,100 |
| Bot | 0.6368 | 0.9949 | 0.7766 | 393 |
| Web Attack - Brute Force | 0.6451 | 0.6921 | 0.6677 | 302 |
| Web Attack - XSS | 0.2335 | 0.4077 | 0.2969 | 130 |
| Infiltration | 1.0000 | 0.7143 | 0.8333 | 7 |
| Web Attack - SQL Injection | 0.1538 | 0.5000 | 0.2353 | 4 |
| Heartbleed | 1.0000 | 1.0000 | 1.0000 | 2 |

## Confusion matrix (rows = true, cols = predicted)

| true \ pred | BENIGN | Bot | DDoS | DoS GoldenEye | DoS Hulk | DoS Slowhttptest | DoS slowloris | FTP-Patator | Heartbleed | Infiltration | PortScan | SSH-Patator | Web Attack - Brute Force | Web Attack - SQL Injection | Web Attack - XSS |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| **BENIGN** | 23609 | 197 | 18 | 10 | 7 | 3 | 3 | 3 | 0 | 0 | 6 | 3 | 35 | 9 | 97 |
| **Bot** | 2 | 391 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| **DDoS** | 10 | 10 | 23980 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| **DoS GoldenEye** | 3 | 0 | 0 | 2049 | 0 | 2 | 0 | 0 | 0 | 0 | 0 | 0 | 3 | 2 | 0 |
| **DoS Hulk** | 2 | 0 | 0 | 0 | 23998 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| **DoS Slowhttptest** | 67 | 0 | 0 | 1 | 1 | 1014 | 17 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| **DoS slowloris** | 33 | 0 | 0 | 2 | 1 | 1 | 1121 | 0 | 0 | 0 | 0 | 0 | 1 | 0 | 0 |
| **FTP-Patator** | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 1588 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| **Heartbleed** | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 2 | 0 | 0 | 0 | 0 | 0 | 0 |
| **Infiltration** | 2 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 5 | 0 | 0 | 0 | 0 | 0 |
| **PortScan** | 1 | 0 | 0 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | 23995 | 1 | 1 | 0 | 0 |
| **SSH-Patator** | 1 | 0 | 0 | 0 | 0 | 0 | 0 | 1 | 0 | 0 | 0 | 1178 | 0 | 0 | 0 |
| **Web Attack - Brute Force** | 0 | 16 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 209 | 0 | 77 |
| **Web Attack - SQL Injection** | 1 | 0 | 0 | 1 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 2 | 0 |
| **Web Attack - XSS** | 0 | 0 | 0 | 1 | 0 | 0 | 0 | 0 | 0 | 0 | 1 | 0 | 75 | 0 | 53 |

## Top features

```
[random_forest]
  init_win_bytes_fwd       0.1251 #######
  fwd_bytes                0.0392 ##
  duration_us              0.0374 ##
  flow_iat_min             0.0360 ##
  fwd_iat_tot              0.0360 ##
  fwd_iat_min              0.0341 ##
  act_data_pkt_fwd         0.0313 #
  fwd_seg_size_avg         0.0291 #
  fwd_header_bytes         0.0291 #
  fwd_pkt_len_mean         0.0286 #
  min_seg_size_fwd         0.0283 #
  active_min               0.0283 #
  fwd_iat_std              0.0281 #
  fwd_pkt_len_max          0.0277 #
  fwd_iat_mean             0.0272 #
[xgboost]
  protocol                 0.1804 ##########
  min_seg_size_fwd         0.1170 #######
  fwd_seg_size_avg         0.0986 #####
  idle_std                 0.0683 ####
  fwd_psh_flags            0.0558 ###
  fwd_packets              0.0551 ###
  fwd_header_bytes         0.0417 ##
  fwd_pkt_len_mean         0.0381 ##
  act_data_pkt_fwd         0.0320 #
  fwd_bytes                0.0222 #
  syn_flag_count           0.0207 #
  fwd_iat_std              0.0187 #
  fwd_urg_flags            0.0170 #
  fwd_iat_tot              0.0162 
  fwd_pkt_len_std          0.0158 
```

## Reproducing

```bash
python scripts/train.py --data data/raw/cicids2017/traffic_labels --out models/
```

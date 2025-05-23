# vah-for-pprl
This repository stores the implementation of Vulnerability-Aware Hardening (VAH), a novel reference set based hardening
technique introduced for PPRL. This work has been submitted at the Conference on Information and Knowledge Management
(CIKM) 2025.

We provide anonymised versions of all data sets used to evaluate VAH in the `data` folder.


### Experimental setups for baselines
We use a default seed value of 42 across all experimental setups. The hardening technique-specific parameters are as follows:

1) Rehashing: window length = 8, step size = 8, k_re = 3
2) BLIP: blip probability = 0.1
3) RBBF: k = 3, sim threshold = 0.4, blip probability = 0.1
4) Windowing-based XOR: window length = 8
5) Diffusion: t = 10

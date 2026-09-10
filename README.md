# Framework for CRIME Automata

A framework for performing compression side-channel attacks using CRIME automata.

This framework implements and expands on the techniques presented in our paper
"*Criminology: Refined Techniques for Compression Side-Channel Attacks*".

## Contents

```
.
├── compressors
│   ├── chromium-zlib
│   ├── cloudflare-zlib
│   ├── flate2-zpipe
│   ├── zlib
│   ├── zlib-go
│   ├── zlib-ng
│   ├── add-submodules.sh
│   ├── __init__.py
│   ├── interface.py
│   └── make.sh
├── crime_automata
├── evaluation
│   ├── results_ampl_paper
│   ├── results_attack_paper
│   ├── eval_ampl.ipynb
│   ├── eval_attack.ipynb
│   ├── requirements.txt
│   └── rupture.py
├── utils
├── example_usage.ipynb
├── LICENSE
├── pyproject.toml
└── README.md
```

- [compressors/](compressors/): DEFLATE compressors, interfaces and setup scripts.
- [crime_automata/](crime_automata/): source code for the CRIME automata framework.
- [evaluation/](evaluation/): evaluation scripts, results and baseline code from the [Rupture](https://github.com/decrypto-org/rupture) framework.
- [utils/](utils/): [script](utils/double-coll.cpp) for finding double collisions in DEFLATE hash functions; there is no need to invoke the script for evaluation.

## Cloning/Downloading

### Cloning

Run `git clone --recurse-submodules <repo>` to clone the repository and its submodules.

### Downloading

Alternatively, one can download the repository directly as a `.zip` file.

After downloading the `.zip` file, extract its contents, change directory to [compressors/](compressors/) and run `./add-submodules.sh` to add the required submodules.

## Requirements and build

### Environment

linux/amd64, Python>=3.10, Jupyter Notebook ([instructions](https://jupyter.org/install#jupyter-notebook)).

### Third-party Python packages

The CRIME automata framework uses the `crc32c` package to compute the hash function in the Cloudflare fork of zlib.
In addition, the evaluation scripts use the following third-party packages: `matplotlib`, `tqdm`.

Run `pip install -r evaluation/requirements.txt` to install the third-party packages mentioned here.

### Compressors

For evaluation, change directory to [compressors/](compressors/) and run `./make.sh` to build test compressors for the compression libraries listed in the table below.

The build script makes use of the following commands: [`cmake`](https://cmake.org/download/), [`go`](https://go.dev/doc/install), and [`cargo`](https://doc.rust-lang.org/cargo/getting-started/installation.html).
Click on their respective links for instructions on installation.

| Compression library | Version | Date |
| --- | --- | --- |
| chromium-zlib | [1.3.2](https://chromium.googlesource.com/chromium/src/third_party/zlib/+/9ffe2c6bfb76203167aa15b468050e3d34891562) | Mar 4, 2026 |
| cloudflare-zlib | [0.3.6](https://github.com/cloudflare/zlib/commit/1252e2565573fe150897c9d8b44d3453396575ff) | Mar 11, 2025 |
| zlib | [1.3.2](https://github.com/madler/zlib/releases/tag/v1.3.2) | Feb 17, 2026 |
| zlib-ng | [2.3.3](https://github.com/zlib-ng/zlib-ng/releases/tag/2.3.3) | Feb 3, 2026 |
| zlib-go | [go1.25.9](https://pkg.go.dev/compress/zlib@go1.25.9) | April 7, 2026 |
| flate2-rust | [1.1.0](https://github.com/rust-lang/flate2-rs/releases/tag/1.1.10) | August 28, 2026 |

The evaluation scripts also require the `gzip` command for testing GNU Gzip (Gzip).
Gzip is usually included in the Linux distribution; run `gzip -V` to check. Otherwise, you can download Gzip [here](https://ftp.gnu.org/gnu/gzip/). We use `gzip 1.14`, released on April 9, 2025.

Note that, with the exception of zlib-ng, which changed its hash function implementation in version [2.2.0](https://github.com/zlib-ng/zlib-ng/releases/tag/2.2.0), 
we expect our framework to be compatible with most compressor versions.

## Installation

*This part is optional and not relevant for evaluation.*

If you wish to install the CRIME automata framework as a Python package, run `pip install .` in the root directory of this repository.
Apart from that, there is no need to perform any action listed in the [Requirements and build](#requirements-and-build) section.

## Evaluation

To reproduce the experiments in the paper, run the two Jupyter notebooks [eval_ampl.ipynb](evaluation/eval_ampl.ipynb) and [eval_attack.ipynb](evaluation/eval_attack.ipynb) in the [evaluation/](evaluation/) directory. 
The results will be visible in the scripts and stored locally at [evaluation/results_ampl/](evaluation/results_ampl/) and [evaluation/results_attack/](evaluation/results_attack/).

Note that each script may take a few hours to run. To perform round-reduced experiments, set `NUM_EVALS` to smaller values in each script.

Modify `ATTACK_RNG_SEED` and `EVAL_RNG_SEED` in each script to use different random seeds for evaluation.
Note that, even with the same seeds, the evaluation results may still be slightly different on different machines.
In particular, the evaluation results on Rupture vary slightly in different runs, likely due to non-determinism in CPython. 

The raw evaluation results and figures we use in the paper are available at [evaluation/results_ampl_paper/](evaluation/results_ampl_paper/) and [evaluation/results_attack_paper/](evaluation/results_attack_paper/).


## Examples

We provide a collection of examples for our framework in [example_usage.ipynb](example_usage.ipynb).

## License

This software is licensed under [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0), with the following exceptions:
- The script [rupture.py](evaluation/rupture.py) is licensed under the MIT license from the [Rupture](https://github.com/decrypto-org/rupture) framework.
- We do not directly distribute the source code of the compressors; please take a look at their respective licenses before use.

## Note

There is currently no plan to maintain this repository.
However, you are welcome to [send me an email](mailto:yuanming.song@inf.ethz.ch) in case you run into any bugs or issues.

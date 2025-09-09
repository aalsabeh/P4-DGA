# P4-DGA
## Source code for the paper "On DGA Detection and Classification using P4 Programmable Switches"

P4-DGA

Files and their description:
  - DGA.p4 : P4 program for parsing domain names, extracting the features, and running the random forest classifier that detects DGAs. The code runs on Intel Tofino chipset and the SDE version is 9.2
  - Control plane directory: contains the control plane program that:
    - Populates the data plane with the bigram frequency values and other rule entries
    - Reads the features from the data plane via message digests
    - Can interface with another program that runs the ML models to enhance the detection, and perform classification of the DGAs
  - ML directory: contains datasets used in the paper under the directory "Datasets". Also, the jupyter notebook "ML.ipynb" contains the classifier that loads the data, performs detection and classification, and reports the accuracies. It is run on a CPU Windows machine.

If you use this repository in your research, please cite the following paper:

```bibtex
@article{alsabeh2024dga,
  title={On dga detection and classification using p4 programmable switches},
  author={AlSabeh, Ali and Friday, Kurt and Kfoury, Elie and Crichigno, Jorge and Bou-Harb, Elias},
  journal={Computers \& Security},
  volume={145},
  pages={104007},
  year={2024},
  publisher={Elsevier}
}

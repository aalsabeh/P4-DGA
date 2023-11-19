# P4-DGA
P4-DGA

Files and their description:
  - DGA.p4 : P4 program for parsing domain names, extracting the features, and running the random forest classifier that detects DGAs. The code runs on Intel Tofino chipset and the SDE version is 9.2
  - Control plane directory: contains the control plane program that:
    - Populates the data plane with the bigram frequency values and other rule entries
    - Reads the features from the data plane via message digests
    - Can interface with another program that runs the ML models to enhance the detection, and perform classification of the DGAs

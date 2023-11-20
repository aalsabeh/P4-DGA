For the datasets, since a lot of the files are larger than 100 MB, I uploaded them to my drive in the below link:

https://drive.google.com/drive/folders/1XYFbNcjlicO4eL84-NfFoyKP4AKVx_WM?usp=share_link

If the below link does not work, please contact me at: "aalsabeh[@]email.sc.edu".


Dataset files description:

	- Github Dataset/CSV/DGA/DGA.csv: CSV file containing the DGA samples with their features. Each row is a malware sample.
	- Github Dataset/CSV/Normal(CTU)/data_no_infection_dns-[42 ... 54]_4.csv: all these CSV files are extracted from the PCAP files of the CTU dataset. They have the same format as DGA.csv, but instead each row is a bening/normal sample. The CTU_13 dataset can be found here: https://www.stratosphereips.org/datasets-ctu13. However, we did some data processing. The pcaps available are cut off before the DNS layer, and there is a separate DNS.log file for the DNS packets. So, we correlate the timestamps between the pcap files and the DNS.log files to build the CSV files that we provide. We also, remove all the IPs related to infected users (botnets).
	
	- Github Dataset/Ngram Scores/: contains files that compute the bigrams and their corresponding frequency values based on the English dictionary and the Top 1m domains.
 
	- Github Dataset/Others/: contains files for the English dictionary, Top 1m domains, and the all Top-level Domains (TLDs).

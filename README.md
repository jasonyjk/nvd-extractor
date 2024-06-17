# nvd-extractor

**User Manual: Fetching and Processing CVEs from NVD**
This script helps to fetch vulnerability data (Common Vulnerabilities and Exposures - CVEs) from the National Vulnerability Database (NVD) using their JSON API. The fetched data is processed and saved to an Excel spreadsheet for easy reference.

**Notes:**
1) Do not modify any part of the source codes except for the API KEY as it is essential for the API requests.
2) Ensure you have a stable internet connection while running the script.
3) Avoid making too many rapid requests to the NVD API to prevent potential rate limiting or bans.

**Pre-requisites:**
Python 3.x installed
Required Python libraries:
pandas
aiohttp
asyncio
datetime

**You can install the libraries using pip:**
pip install pandas 
pip install aiohttp
pip install asyncio
pip datetime

**To run the script, navigate to the script's directory using the terminal or command prompt and run:**
python nvdAPI.py

**Expected Outputs:**
Script will display the start time.
Script will print the status of each page request to the API.
Upon completion, the script will display the end time and save the CVE data to a file named CVE_Data.xlsx in the same directory.

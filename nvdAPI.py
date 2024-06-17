#  Import necessary libraries
import pandas as pd
import math
import time
import datetime
import aiohttp
import asyncio
from requests.exceptions import ConnectionError

#  Define constants for API Key (DO NOT CHANGE), number of records per request, and maximum retries
API_KEY = "ENTER YOUR API KEY HERE"
RECORDS_PER_REQUEST = 2000
MAX_RETRIES = 5

#  Get the start time of the process
start_time = datetime.datetime.now()
print("Time Started: ", start_time.strftime("%Y-%m-%d %H:%M:%S"))


#  Asynchronous function to get total pages
async def get_total_pages(session, num_records):
    #  URL of the API (DO NOT CHANGE)
    base_url = 'https://services.nvd.nist.gov/rest/json/cves/2.0'

    # Parameters for the API request (DO NOT CHANGE)
    params = {
        'resultsPerPage': num_records,
        'startIndex': 0
    }

    #  Headers for the API request (DO NOT CHANGE)
    headers = {
        'apiKey': API_KEY
    }

    #  Retry mechanism for the API call
    retries = 0
    while retries < MAX_RETRIES:
        try:
            #  Make the API call
            async with session.get(base_url, params=params, headers=headers) as response:
                #  If status code is 200, this indicates request is success, process the API response
                if response.status == 200:
                    data = await response.json()
                    total_results = data['totalResults']
                    total_pages = math.ceil(total_results / num_records)
                    return total_pages
                else:
                    print(f"Error: {response.status} - {response.text}")
                    retries += 1
                    time.sleep(5 * retries)  # exponential backoff

        except ConnectionError as e:
            print(f"Connection error: {str(e)}. Retry after 5 seconds.")
            retries += 1
            time.sleep(5)
    print("Failed to get total pages after maximum retries.")
    return None


#  Asynchronous function to retrieve CVE data
async def retrieve_cve_data(session, num_records, num_pages):
    #  URL of the API (DO NOT CHANGE)
    base_url = 'https://services.nvd.nist.gov/rest/json/cves/2.0'
    cve_data = []
    num_requests = num_pages
    start_time = time.time()

    #  Inner asynchronous function to fetch data for a specific page
    async def fetch_data(start_index):
        #  Parameters for the API request (DO NOT CHANGE)
        params = {
            'resultsPerPage': num_records,
            'startIndex': start_index
        }
        #  Headers for the API request (DO NOT CHANGE)
        headers = {
            'apiKey': API_KEY
        }

        #  Retry mechanism for the API call
        retries = 0
        while retries < MAX_RETRIES:
            try:
                # Make the API call
                async with session.get(base_url, params=params, headers=headers) as response:
                    #  If status code is 200, this indicates request is success, process the API response
                    if response.status == 200:
                        # Troubleshoot purpose -> print(response.status)
                        # Troubleshoot purpose -> print("Request headers:", response.request_info.headers)
                        data = await response.json()
                        """  access the value associated with the key 'vulnerabilities' in the dictionary 'data' 
                             JSON response from an API request """
                        vulnerabilities = data['vulnerabilities']
                        for vulnerability in vulnerabilities:
                            #  Call the process_vulnerability function
                            cve_data.append(process_vulnerability(vulnerability))
                        return
                    else:
                        print(f"Error: {response.status} - {await response.text()}")
                        retries += 1
                        await asyncio.sleep(5 * retries)  # exponential backoff
            except (
            aiohttp.client_exceptions.ClientPayloadError, aiohttp.client_exceptions.ServerDisconnectedError) as e:
                print(f"Connection error: {str(e)}. Retry after 5 seconds.")
                retries += 1
                # await time.sleep(6)
                await asyncio.sleep(5)
        print("Max retries reached. Skipping current request.")

    #  Asynchronous request management for all pages
    tasks = []
    for request_num in range(num_requests):
        start_index = request_num * num_records
        await fetch_data(start_index)
        print(f"\nRequest page {request_num + 1}/{num_requests} completed")
        # tasks.append(fetch_data(start_index))
        await asyncio.sleep(6)  # Sleep for 6 seconds after each request (*BEST PRACTICE*)

    await asyncio.gather(*tasks)
    elapsed_time = time.time() - start_time  # Calculate total time taken to process all request
    print(f"\nAll requests completed. Total time taken: {elapsed_time:.2f} seconds.")
    return cve_data  # CVE data to be saved to Excel spreadsheet


#  Function to process each vulnerability item
def process_vulnerability(vulnerability):
    #  Extract specific pieces of CVE information from the vulnerability dictionary (*JSON structure*)
    cve_id = vulnerability['cve']['id']
    published_date = vulnerability['cve']['published']
    last_modified_date = vulnerability['cve']["lastModified"]
    description = vulnerability['cve']['descriptions'][0]['value']

    #  Check each CVEs whether they are using cvssMetricV31, cvssMetricV3 or cvssMetricV2
    if 'cvssMetricV31' in vulnerability['cve']['metrics']:
        version = vulnerability['cve']['metrics']['cvssMetricV31'][0]['cvssData']['version']
        vector_string = vulnerability['cve']['metrics']['cvssMetricV31'][0]['cvssData']['vectorString']
        access_vector = vulnerability['cve']['metrics']['cvssMetricV31'][0]['cvssData']['attackVector']
        access_complexity = vulnerability['cve']['metrics']['cvssMetricV31'][0]['cvssData']['attackComplexity']
        confidentiality_impact = vulnerability['cve']['metrics']['cvssMetricV31'][0]['cvssData']['confidentialityImpact']
        integrity_impact = vulnerability['cve']['metrics']['cvssMetricV31'][0]['cvssData']['integrityImpact']
        availability_impact = vulnerability['cve']['metrics']['cvssMetricV31'][0]['cvssData']['availabilityImpact']
        base_score = vulnerability['cve']['metrics']['cvssMetricV31'][0]['cvssData']['baseScore']
        base_severity = vulnerability['cve']['metrics']['cvssMetricV31'][0]['cvssData']['baseSeverity']
        exploitability_score = vulnerability['cve']['metrics']['cvssMetricV31'][0]['exploitabilityScore']
        impact_score = vulnerability['cve']['metrics']['cvssMetricV31'][0]['impactScore']
    elif 'cvssMetricV30' in vulnerability['cve']['metrics']:
        version = vulnerability['cve']['metrics']['cvssMetricV30'][0]['cvssData']['version']
        vector_string = vulnerability['cve']['metrics']['cvssMetricV30'][0]['cvssData']['vectorString']
        access_vector = vulnerability['cve']['metrics']['cvssMetricV30'][0]['cvssData']['attackVector']
        access_complexity = vulnerability['cve']['metrics']['cvssMetricV30'][0]['cvssData']['attackComplexity']
        confidentiality_impact = vulnerability['cve']['metrics']['cvssMetricV30'][0]['cvssData']['confidentialityImpact']
        integrity_impact = vulnerability['cve']['metrics']['cvssMetricV30'][0]['cvssData']['integrityImpact']
        availability_impact = vulnerability['cve']['metrics']['cvssMetricV30'][0]['cvssData']['availabilityImpact']
        base_score = vulnerability['cve']['metrics']['cvssMetricV30'][0]['cvssData']['baseScore']
        base_severity = vulnerability['cve']['metrics']['cvssMetricV30'][0]['cvssData']['baseSeverity']
        exploitability_score = vulnerability['cve']['metrics']['cvssMetricV30'][0]['exploitabilityScore']
        impact_score = vulnerability['cve']['metrics']['cvssMetricV30'][0]['impactScore']
    elif 'cvssMetricV2' in vulnerability['cve']['metrics']:
        version = vulnerability['cve']['metrics']['cvssMetricV2'][0]['cvssData']['version']
        vector_string = vulnerability['cve']['metrics']['cvssMetricV2'][0]['cvssData']['vectorString']
        access_vector = vulnerability['cve']['metrics']['cvssMetricV2'][0]['cvssData']['accessVector']
        access_complexity = vulnerability['cve']['metrics']['cvssMetricV2'][0]['cvssData']['accessComplexity']
        confidentiality_impact = vulnerability['cve']['metrics']['cvssMetricV2'][0]['cvssData']['confidentialityImpact']
        integrity_impact = vulnerability['cve']['metrics']['cvssMetricV2'][0]['cvssData']['integrityImpact']
        availability_impact = vulnerability['cve']['metrics']['cvssMetricV2'][0]['cvssData']['availabilityImpact']
        base_score = vulnerability['cve']['metrics']['cvssMetricV2'][0]['cvssData']['baseScore']
        base_severity = vulnerability['cve']['metrics']['cvssMetricV2'][0]['baseSeverity']
        exploitability_score = vulnerability['cve']['metrics']['cvssMetricV2'][0]['exploitabilityScore']
        impact_score = vulnerability['cve']['metrics']['cvssMetricV2'][0]['impactScore']
    else:
        #  Some of the latest CVEs might not have all the information ready, set dummy values
        version = 'N/A'
        vector_string = 'N/A'
        access_vector = 'N/A'
        access_complexity = 'N/A'
        confidentiality_impact = 'N/A'
        integrity_impact = 'N/A'
        availability_impact = 'N/A'
        base_score = 'N/A'
        base_severity = 'N/A'
        exploitability_score = 'N/A'
        impact_score = 'N/A'

    #  Return all extracted information
    return [cve_id, description, published_date, last_modified_date, version, vector_string, access_vector,
            access_complexity, confidentiality_impact, integrity_impact, availability_impact, base_score,
            base_severity, exploitability_score, impact_score]


#  Function to save CVE data to Excel spreadsheet
def save_cve_data_to_excel(cve_data):
    df = pd.DataFrame(cve_data, columns=['CVE ID', 'Description', 'Published Date', 'Last Modified Date', 'Version',
                                         'Vector String', 'Access Vector', 'Access Complexity',
                                         'Confidentiality Impact', 'Integrity Impact', 'Availability Impact',
                                         'Base Score', 'Base Severity', 'Exploitability Score', 'Impact Score'])
    #  Data saved to Excel spreadsheet
    df.to_excel('CVE_Data.xlsx', index=False)


#  Main asynchronous function
async def main():
    async with aiohttp.ClientSession() as session:
        num_pages = await get_total_pages(session, RECORDS_PER_REQUEST)
        if num_pages is not None:
            cve_data = await retrieve_cve_data(session, RECORDS_PER_REQUEST, num_pages)
            save_cve_data_to_excel(cve_data)

            #  Get the end time of the process
            end_time = datetime.datetime.now()  # corrected this line
            print("Time Completion: ", end_time.strftime("%Y-%m-%d %H:%M:%S"))


#  Run the main function
asyncio.run(main())
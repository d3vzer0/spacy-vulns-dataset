from datetime import datetime, timedelta
from utils.nvd import NVD
import csv
import typer
import dateparser
import warnings

warnings.filterwarnings(
    "ignore",
    message="The localize method is no longer necessary, as this time zone supports the fold attribute",
)

app = typer.Typer()

@app.command()
def get_cves(start_date: str, end_date: str, max_results: int = 2000, output_path: str = './dataset/cves.csv'):
    ''' Get CVEs from the NVD API'''

    # Convert date string to date object with correct formatting for the API call
    start_date_fmt = dateparser.parse(start_date).strftime('%Y-%m-%dT%H:%M:%S:000 UTC-00:00')
    end_date_fmt = dateparser.parse(end_date).strftime('%Y-%m-%dT%H:%M:%S:000 UTC-00:00')

    nvd_params = {
        'resultsPerPage': max_results,
        'pubStartDate': start_date_fmt,
        'pubEndDate':end_date_fmt
    }

    # Get CVES between specified start and end date
    with NVD(params=nvd_params) as nvd:
        all_cves = nvd.cves

    csv_header = ['cve', 'description']
    with open(output_path, 'w') as output_csv:
        cvewriter = csv.DictWriter(output_csv, delimiter=',', fieldnames=csv_header)
        cvewriter.writeheader()
        for cve in all_cves:
            cvewriter.writerow({'cve':cve['cve']['CVE_data_meta']['ID'], 
                'description': cve['cve']['description']['description_data'][0]['value']})
            
if __name__ == '__main__':
    app()



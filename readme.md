Quick Start
1. Clone or download this repo
git clone https://github.com/your-username/pii-scrubber.git
cd pii-scrubber
2. Run the script
python detector_full_candidate_name.py input.csv output.csv
input.csv → your source file (must have columns: record_id, Data_json)
output.csv → the new file with redacted PII
If you don’t specify an output filename, it will default to redacted_output.csv.

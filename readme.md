Step By Step Guide:

1. Clone or download this repo
>> git clone https://github.com/cypher-28/SOC.git

2. Run the script

>> python3 detector_full_candidate_name.py input.csv output.csv

Note:-
-- input.csv → your source file (must have columns: record_id, Data_json)
-- output.csv → the new file with redacted PII
-- If you don’t specify an output filename, it will default to redacted_output.csv.

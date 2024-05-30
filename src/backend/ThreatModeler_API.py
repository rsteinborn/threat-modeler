import openai
import pandas as pd
import os
from openai import OpenAI
from tqdm import tqdm 

client = OpenAI()

def parse_scenario_lines(lines):
    """Parse lines from a scenario, including handling structured table-like data."""
    scenario_dict = {}
    for line in lines:
        # Check if the line looks like a table row or structured data
        if '|' in line:
            parts = [part.strip() for part in line.split('|') if part.strip()]
            if len(parts) == 20:  # Assuming we know the table structure exactly
                headers = ["Source Name", "Source Type", "Source Description", "Target Name", "Target Type", 
                           "Target Description", "Relationship", "Auth Required", "Encryption", "Encryption Type", 
                           "Data Format", "Frequency", "Data Integrity", "Access Type", "Access Target", 
                           "Network Protocol", "Communication Channel", "Credential Storage", "Interactor", "Threat"]
                scenario_dict.update(dict(zip(headers, parts)))
        elif ':' in line:
            key, value = line.split(':', 1)
            scenario_dict[key.strip()] = value.strip()
    return scenario_dict

def generate_dfd_scenarios(api_key, num_scenarios):
    openai.api_key = api_key
    scenarios_per_request = 20  # Adjust based on what the API can handle comfortably
    total_scenarios = []

     # Initialize tqdm progress bar
    pbar = tqdm(total=num_scenarios, desc="Generating scenarios")

    for _ in range(0, num_scenarios, scenarios_per_request):
        scenarios_needed = min(scenarios_per_request, num_scenarios - len(total_scenarios))
        prompt = (
            f"Generate {scenarios_needed} DFD scenarios with the following fields: "
            "Source Name, Source Type, Source Description, Target Name, Target Type, Target Description, "
            "Relationship, Auth Required, Encryption, Encryption Type, Data Format, Frequency, Data Integrity, "
            "Access Type, Access Target, Network Protocol, Communication Channel, Credential Storage, Interactor, Threat."
            "Each scenario should be unique and reflect a real-world use case.\n"
            "For the threats, please only use one of the following:\n"
            "    Cross-Site Request Forgery (CSRF)\n"
            "    Denial of Service (DoS)\n"
            "    Distributed Denial of Service (DDoS)\n"
            "    Drive-by Download Attacks\n"
            "    Password Attack\n"
            "    Credential Stuffing\n"
            "    Side-Channel Attack\n"
            "    Directory Traversal\n"
            "    Remote Code Execution (RCE)\n"
            """It is important that each row represents a realistic relationship between two entities, therefore a relationship with no threat of course also is possible.
            For the Source Type and Target Type, categorize each Source into one of the following: Database, Web Application, Device, Service, User.
            For the Auth Required, choose one of the following: Yes, No.
            For the Encryption, choose one of the following: Yes, No.
            For the Encryption Type, choose one of the following: Symmetric, Asymmetric, Hashing, TLS/SSL, None.
            For the Data Format, choose one of the following: JSON, XML, CSV, Binary, Plain Text.
            For the Frequency, choose one of the following: Real-Time, Batch, Periodic, On-Demand, Event-Driven.
            For the Data Integrity, choose one of the following: Checksum, Hash, Digital Signature, None.
            For the Access Type, choose one of the following: Read, Write, Read&Write, Execute, None.
            For the Access Target, choose one of the following: Database, File System, Web Service/API, Message Queue, None.
            For the Network Protocol, choose one of the following: HTTP/HTTPS, FTP/SFTP, TCP/IP, UDP, None.
            For the Communication Channel, choose one of the following: Wired, Wireless, Virtual Private Network, Bluetooth, None.
            For the Credential Storage, choose one of the following: Plain Text, Hashed, Encrypted, Environment Variable, Secure Vault.
            For the Interactor, choose one of the following: User, System, Application, Device, None.
            """
        )
        response = client.chat.completions.create(
            model="gpt-3.5-turbo",
            messages=[
                {"role": "system", "content": "You are a helpful assistant."},
                {"role": "user", "content": prompt}
            ]
        )

        scenarios_text = response.choices[0].message.content.strip()
        scenarios = scenarios_text.split("\n\n")
        
        for scenario in scenarios:
            lines = scenario.split('\n')
            parsed_scenario = parse_scenario_lines(lines)
            if parsed_scenario:
                total_scenarios.append(parsed_scenario)
        pbar.update(scenarios_needed)  # Update progress bar after each batch
    
    pbar.close()  # Close the progress bar after all scenarios are processed
    return total_scenarios

def create_dataframe(scenarios):
    return pd.DataFrame(scenarios)

def append_to_csv(df, filename):
    if os.path.exists(filename):
        existing_df = pd.read_csv(filename)
        combined_df = pd.concat([existing_df, df], ignore_index=True)
    else:
        combined_df = df
    combined_df.to_csv(filename, index=False)

if __name__ == "__main__":
    api_key = "" #Insert OpenAI Key here
    num_scenarios = 100 #anzahl zeilen hier anpassen
    scenarios = generate_dfd_scenarios(api_key, num_scenarios)
    df = create_dataframe(scenarios)
    append_to_csv(df, "threats.csv")
    print("DFD scenarios generated and saved.")


 
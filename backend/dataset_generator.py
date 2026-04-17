import pandas as pd
import random

def generate_data(samples=2000):
    data = []
    for _ in range(samples):
        traffic_type = random.choice(["outbound_web", "inbound_web", "malicious_probe", "normal_dns", "raw_ip"])
        
        if traffic_type == "outbound_web":
            src_port = random.randint(1024, 65535)
            dst_port = random.choice([80, 443])
            length = random.randint(40, 2500)
            malicious = 0
            
        elif traffic_type == "inbound_web":
            src_port = random.choice([80, 443])
            dst_port = random.randint(1024, 65535)
            length = random.randint(40, 2500)
            malicious = 0
            
        elif traffic_type == "normal_dns":
            src_port = random.randint(1024, 65535)
            dst_port = 53
            length = random.randint(40, 2500)
            malicious = 0

        elif traffic_type == "raw_ip":
            src_port = 0
            dst_port = 0
            length = random.randint(40, 2500)
            malicious = 0
            
        else: # malicious_probe
            src_port = random.randint(1024, 65535)
            dst_port = random.choice([21, 23, 3389, 4444, 445])
            length = random.randint(40, 2500)
            malicious = 1

        data.append([
            src_port, dst_port, length, malicious
        ])

    df = pd.DataFrame(data, columns=[
        "src_port", "dst_port", "length", "label"
    ])
    df.to_csv("dataset.csv", index=False)

if __name__ == "__main__":
    generate_data()

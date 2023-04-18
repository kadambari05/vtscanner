import tkinter as tk
import os
import sys
import time
import json
import requests
import hashlib

def store_input():
    global MP
    MP = entry.get()
    print(f"Enter file path: {MP}")
    vtscan = VTScan()
    vtscan.run(MP)
root = tk.Tk()
label = tk.Label(root, text="Enter file path:")
label.pack()

entry = tk.Entry(root)
entry.pack()

button = tk.Button(root, text="Store input", command=store_input)
button.pack()

# VirusTotal API key
VT_API_KEY = "d72bb4d55f5e12601fb0cfcebf5435e9edfd4fe00bc179ae3c98c2961c8bf3ac"

# VirusTotal API v3 URL
VT_API_URL = "https://www.virustotal.com/api/v3/"

class VTScan:
    def __init__(self):
        self.headers = {
            "x-apikey" : VT_API_KEY,
            "User-Agent" : "vtscan v.1.0",
            "Accept-Encoding" : "gzip, deflate",
        }

    def run(self, malware_path):
        self.upload(malware_path)
        self.analyse()
    def upload(self, malware_path):
        print ("upload file: " + malware_path + "...")
        self.malware_path = malware_path
        upload_url = VT_API_URL + "files"
        files = {"file" : (
            os.path.basename(malware_path),
            open(os.path.abspath(malware_path), "rb"))
        }
        print ("upload to " + upload_url)
        res = requests.post(upload_url, headers = self.headers, files = files)
        if res.status_code == 200:
            result = res.json()
            self.file_id = result.get("data").get("id")
            print (self.file_id)
            print ("successfully upload PE file: OK")
        else:
            print ("failed to upload PE file :(")
            print ("status code: " + str(res.status_code))
            sys.exit()

    def analyse(self):
        print(MP)
        print ("get info about the results of analysis...")
        analysis_url = VT_API_URL + "analyses/" + self.file_id
        res = requests.get(analysis_url, headers = self.headers)
        if res.status_code == 200:
            result = res.json()
            status = result.get("data").get("attributes").get("status")
            if status == "completed":
                stats = result.get("data").get("attributes").get("stats")
                results = result.get("data").get("attributes").get("results")
                malicious=stats.get("malicious")
                print(malicious)
                print ("malicious: " + str(stats.get("malicious")))
                print ("undetected : " + str(stats.get("undetected")))
                print ()
                for k in results:
                    if results[k].get("category") == "malicious":
                        print("==================================================")
                        print(results[k].get("engine_name"))
                        print("version : " + results[k].get("engine_version"))
                        print("category : " + results[k].get("category"))
                        print("result : " + results[k].get("result"))
                        print("method : " + results[k].get("method"))
                        print("update : " + results[k].get("engine_update"))
                        print("==================================================")
                        print()
                print ("successfully analyse: OK")
                sys.exit()
            elif status == "queued":
                print ("status QUEUED...")
                with open(os.path.abspath(self.malware_path), "rb") as f:
                    b = f.read()
                    hashsum = hashlib.sha256(b).hexdigest()
                    # self.info(hashsum)
        else:
            print ("failed to get results of analysis :(")
            print ("status code: " + str(res.status_code))
            sys.exit

def run_vtscan():
    global MP
    MP = entry.get()
    vtscan = VTScan()
    vtscan.run(MP)

scan_button = tk.Button(root, text="Scan for viruses", command=run_vtscan)
scan_button.pack()
root.geometry("800x600")
root.mainloop()
run_vtscan()
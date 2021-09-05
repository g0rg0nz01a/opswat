import requests
import hashlib
import time

apikey = "{apikey}"                                                 # Enter global apikey.
working_dir = ["sample_txt.txt", "sample_txt_unknown.txt"]          # Working directory keeps the files in a 
                                                                    # controlled environment to be worked on.
                                                                    # Note: pathlib module to implement local host file handling.
def getFile():
    sample_file = ""
    while sample_file == "":
        user_input = input("Enter file name and extension: ")       # User enters file in current directory.
        if user_input not in  working_dir:                          # Validates that file is in directory 
            print("Please enter a valid file")                      # to be worked on.
            continue                                                 
        else:
            sample_file = user_input
            break
    return sample_file                                              # Returns valid working file.

def hashFile(sample_file):
    with open(sample_file, "rb") as hash_file:                      # Opens file in binary read mode.
        buffer = hash_file.read()                                   # Allocates space for hash file.
        md5_hash = hashlib.md5(buffer).hexdigest()                  # Assigns hash values to variables.
        sha1_hash = hashlib.sha1(buffer).hexdigest()                
        sha256_hash = hashlib.sha256(buffer).hexdigest()
        hash_tup = (md5_hash, sha1_hash, sha256_hash)               # Creates tuple to hold hash variables. 
        return hash_tup


def uploadFile(sample_file):

    url = "https://api.metadefender.com/v4/file"                    # Uploads file in original format and passes it   
    headers = {                                                     # through the metadefender cloud scanner.
        "apikey": apikey                                            
    }                                                               

    response = requests.request("POST",url, files={"form_field_name": sample_file}, headers=headers)        
    data_id = response.json()["data_id"]                                                                    # Key is "data_id" value is str.
    return data_id                                                                                          # Returns an indexed json object.     

def getDataID(data_id):
    url = "https://api.metadefender.com/v4/file/" + data_id         # Checks for scan results using data_id.
    headers = {
        "apikey": apikey
    }
    
    response = requests.request("GET", url, headers=headers)        # Once data_id is verified and retrieves info 
    md5_hash = response.json()["file_info"]["md5"]                  # stores hash values in a tuple to pass into checkHash().
    sha1_hash = response.json()["file_info"]["sha1"]
    sha256_hash = response.json()["file_info"]["sha256"]
    hash_tup = (md5_hash, sha1_hash, sha256_hash)
    return hash_tup  

def checkHash(hash_tup):
    response = ""

    url = "https://api.metadefender.com/v4/hash/"                   # Checks for scan results using hash.
    headers = {
        "apikey": apikey
    }

    for i in hash_tup:                                              # Iterates through hash tuple to check each hash.
        check = requests.request("GET", url + i, headers=headers)   
        response = check                                            # Note: Uses three check everytime, limit problem arises.
        return response 

def outputDataHash(response):

    found_occurence = False                                         # Makes sure there are results to be printed. 

    while not found_occurence:                                      
        scan_details = response.json()["scan_results"]["scan_details"]  
        found_occurence = True
        for i in scan_details:                                      # Grabs the headers of the results of the individual engines.
            print("Engine: ", i)                                    # Uses engine name as key to iterate through scan details.
            for k, v in scan_details[i].items():                    
                if k == "threat_found" and v == "":                 # Prints key-value pairs, or "none" if threat_found string is empty
                    v = "none"                                       
                print(k, ": ",v)
                if k == "threat_found":
                    print("----------------------------")           # Horizontal bar at end of each engine results for visibility
                    


def main():
    working_file = getFile()                                        # Get working file from user input.
    hash_tup = hashFile(working_file)                               # Creating the hash tuple for retrieving results.
    response = checkHash(hash_tup)                                  # Retrieving results.
    
    while response.status_code != 200:                              # If no results from checkHash(), upload and scanning 
        print("Commencing upload and scan.")                        # the file, until it is available. 
        data_id = uploadFile(working_file)
        time.sleep(5)                                               # Giving the engines enough time to scan and return results.
        response = checkHash(getDataID(data_id))
       
        

    outputDataHash(response)                                        # Parses json objects and formats results.
    


if __name__ == "__main__":
    main()
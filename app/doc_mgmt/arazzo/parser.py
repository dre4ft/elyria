import json
import yaml 
from yaml import safe_load



#pqrser les steps
#parser des parameters 
#logiaue des Criteria 
#retour des outputs 
#$link resolver 


def _open_file(path:str):
    if path.split(".")[1] == "json":
        with open(path,"r")as file:
            content = json.load(file) 
    elif path.split(".")[1] == "yml" or path.split(".")[1] == "yaml" :
        with open(path,"r")as file:
            content = safe_load(file)
    else :
        raise Exception("file type must be either json,yml or yaml")
    if _validate_mandatory_filed(content):
        return content
    else :
        raise Exception("file should follow arazzo specification")
    
def _validate_mandatory_filed(content : dict):
    return content.get("arazzo") and  content.get("info") and  content.get("sourceDescriptions") and  content.get("workflows") and  content.get("components")



def _get_spec(content:dict):
    return content["sourceDescriptions"]["url"]
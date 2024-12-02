import json
import os

#top 3 of each https://www.researchgate.net/publication/349828209_POPULAR_PYTHON_LIBRARIES_AND_THEIR_APPLICATION_DOMAINS

files = ['aiobotocore-2.15.2.json','boto3-1.35.59.json','botocore-1.35.59.json','certifi-2024.8.30.json','charset_normalizer-3.4.0.json', 
'idna-3.10.json', 'requests-2.32.3.json', 'setuptools-75.5.0.json', 'typing_extensions-4.12.2.json', 'urllib3-2.2.3.json']

cwes = []
bval = []

def append_data(data):
    #CWE-values
    for i in data['results']:
        appended=False
        cur_id = i["issue_cwe"]["id"]
        for entry in cwes:  #increment if already exists
            if entry["key"]==cur_id: 
                entry["value"]+=1
                appended=True
                break

        if(not appended):
            cwes.append({"key": cur_id, "value": 1})  # Add a new key-value pair

    #B-Values
    for i in data['results']:
        appended=False
        cur_id = i["test_id"]
        for entry in bval:  #increment if already exists
            if entry["key"]==cur_id and entry["cwe"]==i["issue_cwe"]["id"]: 
                entry["value"]+=1
                appended=True
                break

        if(not appended):
            bval.append({"key": cur_id, "cwe": i["issue_cwe"]["id"], "value": 1})  # Add a new key-value pair

def cweTable(cwe, blist):
    totalCount = 0
    b1freq = 0

    for entry in blist: #get B101 values
        if entry["key"]=="B101":
            b1freq+=entry["value"]
    for entry in cwe: #get total CWEs
        totalCount+=entry["value"]

    analysis = []
    for entry in cwe:
        bcount = 0
        for bval in blist: #get b101 counts/cwe
            if bval["cwe"]==entry["key"] and bval["key"]=="B101":
                bcount+=bval["value"]
                break

        analysis.append({"key": entry["key"], "abs": entry["value"], "rel": (entry["value"]/totalCount)*100, "abs_b": entry["value"]-bcount, "rel_b": ((entry["value"]-bcount)/(totalCount-b1freq))*100})

    return analysis

def BTable(bval):
    preanalysis = []
    analysis = []

    for entry in bval:  #Reduce to B-value & count
        cur_id = entry["key"]
        appended = False
        for val in preanalysis:
            if val["key"]==cur_id: 
                val["value"]+=entry["value"]
                appended=True

        if(not appended):
            preanalysis.append({"key": cur_id, "value": entry["value"]})  # Add a new key-value pair

    for entry in preanalysis:
        cur_id = entry["key"][:2]
        appended = False
        for val in analysis:
            if val["key"]==cur_id:
                val["abs"]+=entry["value"]
                if entry["key"]!="B101":
                    val["abs_b"]+=entry["value"]
                appended=True

        if(not appended):
            if entry["key"]!="B101":
                analysis.append({"key": cur_id, "abs": entry["value"], "rel": 0, "abs_b": entry["value"], "rel_b": 0})
            else:
                analysis.append({"key": cur_id, "abs": entry["value"], "rel": 0, "abs_b": 0, "rel_b": 0})

    #Calculate percentages
    totalCount = 0
    b101Count = 0 #amount of non-b101 entries
    for entry in analysis: 
        totalCount+=entry["abs"]
        b101Count+=entry["abs_b"]

    for entry in analysis:
        entry["rel"]=(entry["abs"]/totalCount)*100
        entry["rel_b"]=(entry["abs_b"]/b101Count)*100
            

    return analysis


# Open and read the JSON file

for i in os.listdir("report"):
    file_path = os.path.join("report", i)
    with open(file_path, 'r') as file:
        data = json.load(file)
    append_data(data)

analysisCWE = cweTable(cwes, bval)
analysisB = BTable(bval)

sorted_CWE = sorted(analysisCWE, key=lambda x: str(x['key']))
sorted_B = sorted(analysisB, key=lambda x: x['abs'], reverse=True)


print("CWE TABLE")
print("\\begin{tabularx}{\\textwidth}{| X | X | X | X | X | X |}[H]\hline")
print("Category of potential vulnerability & Code & Absolute Frequency & Percentage of the total number of vulnerabilities & Absolute frequency without B101 & Percentage of the total number of vulnerabilities \cr \hline")
for i in sorted_CWE:
    print(" & CWE-" + str(i["key"]) + " & " + str(i["abs"]) + " & " + str(round(i["rel"],2)) + " & " + str(i["abs_b"]) + " & " + str(round(i["rel_b"],2)) + " \cr \hline")
print("\end{tabularx}")

print("\n \nB-Table")    
print("\\begin{tabularx}{\\textwidth}{| X | X | X | X | X | X | X |}[H]\hline")
print("Category & Values in total & Percentage of the total number for the category & Total number without the values of B101 & Percentage of the total number for the category \cr \hline")
for i in sorted_B:
    print(str(i["key"]) + "xx & " + str(i["abs"]) + " & " + str(round(i["rel"],2)) + " & " + str(i["abs_b"]) + " & " + str(round(i["rel_b"],2)) + " \cr \hline")
print("\end{tabularx}")

# for i in analysisCWE:
#     print(i)
# for i in sorted_B:
    # print(i)

    



file.close()
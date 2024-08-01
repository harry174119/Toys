################################# TO DO ########################################
#
# This version of this script:
## Only supports Snyk projects with GitHub origin 
## Only create/update/close Jira issues for vulnerabilities in dependency (not for vulnerabilities in code and license issues)
#
# To do:
## Create/update/close Jira issues for vulnerabilities in code and license issues
## To be updated...
################################# TO DO ########################################


################################# Script usage #################################
### Usage
# python3 snyk_jira_sync.py --jiraEmail <jiraEmail> --jiraToken <jiraToken> -- snykToken <snykToken> --snykOrgId <snykOrgId> -F <functionName> --<argumentName> <argumentValue>
### To get jiraToken:
# 1. Go to https://id.atlassian.com/manage-profile/security/api-tokens
# 2. Log in with your Jira account
# 3. Click on "Create API token"
# 4. Enter a label for the token
# 5. Click on "Create"
# 6. Copy the token and save it in a safe place
### to get snykToken:
# 1. Go to https://app.snyk.io/login
# 2. Log in with your Snyk account
# 3. Click on your profile picture on the top right corner
# 4. Click on "Account settings"
# 5. Click on "API token" on the left panel
# 6. Click on "Create API token"
# 7. Enter a name for the token
# 8. Click on "Create API token"
# 9. Copy the token and save it in a safe place
### To get snykOrgId:
# 1. Go to https://app.snyk.io/login
# 2. Log in with your Snyk account
# 3. Click on your profile picture on the top right corner
# 4. Click on "Account settings"
# 5. Click on "Organizations" on the left panel
# 6. Click on the organization you want to get the ID
################################# Script usage #################################


################################# Create Jira issues ###########################
### Create Jira issues for single Snyk project
# python3 snyk_jira_sync.py --jiraEmail <jiraEmail> --jiraToken <jiraToken> -- snykToken <snykToken> -F create_jira_issues_for_snyk_project --snykProjectId <snykProjectId>
### Create Jira issues for all in-scope Snyk projects
# python3 snyk_jira_sync.py --jiraEmail <jiraEmail> --jiraToken <jiraToken> -- snykToken <snykToken> -F create_jira_issues
################################################################################


################################# Update Jira issues ###########################
### Update Jira issues for single Snyk project
# python3 snyk_jira_sync.py --jiraEmail <jiraEmail> --jiraToken <jiraToken> -- snykToken <snykToken> -F update_jira_issues_for_snyk_project --snykProjectId <snykProjectId>
### Update Jira issues for all in-scope Snyk projects
# python3 snyk_jira_sync.py --jiraEmail <jiraEmail> --jiraToken <jiraToken> -- snykToken <snykToken> -F update_jira_issues
################################################################################


################################# Close Jira issues ############################
### Close Jira issues for single product
# python3 snyk_jira_sync.py --jiraEmail <jiraEmail> --jiraToken <jiraToken> -- snykToken <snykToken> -F close_jira_issues --productName <productName>
### Close Jira issues for all products
# python3 snyk_jira_sync.py --jiraEmail <jiraEmail> --jiraToken <jiraToken> -- snykToken <snykToken> -F close_jira_issues
################################################################################


################################# Run script in dry mode #######################
### add option --dryRun to run the script in dry mode (only print out the actions without actually executing them)
# python3 snyk_jira_sync.py --jiraEmail <jiraEmail> --jiraToken <jiraToken> -- snykToken <snykToken> -F create_jira_issues --dryRun
# python3 snyk_jira_sync.py --jiraEmail <jiraEmail> --jiraToken <jiraToken> -- snykToken <snykToken> -F close_jira_issues --dryRun
################################################################################


################################# How to update Product dictionary #############
### Step 1: Retrieve all repositories imported to Snyk, run the following command:
# python3 snyk_jira_sync.py -F retrieve_repositories_from_snyk
### Step 2: Update the Products dictionary by adding repositories from "katalonOther" to the corresponding product
### Step 3: Add new product to the Jira project and Products dictionary if needed
### Step 4: Get Jira product ID for each product: change Product field in Jira issue -> retrieve Jira issue data -> Find Jira product ID in "customfield_10698".
# python3 snyk_jira_sync.py -F retrieve_jira_issue --jiraIssueKey <jiraIssueKey>
### Step 3: Update "productName" and "jiraProductId" in find_product_for_snyk_project() function
################################################################################


import argparse
import requests
from requests.auth import HTTPBasicAuth
import json

# Define the global Products dictionary
Products = {
    "katalonStudio": [
        "katalon-studio/katalon(main)",
        "katalon-studio/katalon(release-9.0.0)",
        "katalon-studio/docker-images",
        "katalon-studio/docker-images(release-9.0.0)",
        "katalon-studio/katalon-webview(master)",
        "katalon-studio/katalon-studio-platform",
        "katalon-studio/katalon-studio-record-utility",
        "katalon-studio/katalon-studio-testrail-plugin",
        "katalon-studio/katalon-studio-jenkins-plugin",
        "katalon-studio/katalon-studio-jira-plugin",
        "katalon-studio/studio-update-package-generator",
        "katalon-studio/katalon-setup(main)",
        "katalon-studio/katalon-gradle-plugin(master)",
        "katalon-studio/katalon-studio-sealights-plugin",
        "katalon-studio/katalon-studio-slack-plugin",
        "katalon-studio/katalon-studio-applitools-plugin",
        "katalon-studio/katalon-studio-basic-report-plugin",
        "katalon-studio/katalon-studio-microsoftteam-keywords-plugin",
        "katalon-studio/katalon-studio-zip-keywords-plugin",
    ],
    "katalonTestOps": [
        "katalon-studio/katalon-testops-private(master)",
        "katalon-studio/katalon-agent",
        "katalon-studio/katalon-reports-analytics(main)",
        "katalon-studio/katalon-jira-cloud-add-on(master)",
        "katalon-studio/test-management(main)"
    ],
    "katalonTestCloud": [
        "katalon-studio/katalon-testcloud", 
        "katalon-studio/testcloud-auth",
        "katalon-studio/testcloud-grid",
        "katalon-studio/testcloud-tunnel",
        "katalon-studio/katalon-testcloud-agent-private",
        "katalon-studio/testcloud-provisioning",
        "katalon-studio/testcloud-execution-env",
        "katalon-studio/testcloud-execution-env(main)"
    ],
    "katalonCloudStudio": [
        "katalon-studio/katalon-g5",
        "katalon-studio/katalon-ui"
    ],
    "katalonOne": [
        "katalon-studio/katalon-one(develop)",
        "katalon-studio/katalon-testops-private(admin)"
    ],
    "katalonAI": [
        "katalon-studio/katalon-atg(main)",
        "katalon-studio/katalon-genai(main)",
        "katalon-studio/katalon-testops-engine-python(master)"
    ],
    "katalonIAM": [
        "katalon-studio/katalon-platform(main)"
    ],
    "katalonWebsite": [
        "katalon-studio/katalon-backend-nodejs",
        "katalon-studio/mkt-website-nextjs",
        "katalon-studio/strapi-cms"
    ],
    "katalonAcademy": [
        "katalon-studio/website-katalon-training"
    ],
    "katalonDocs": [
        "katalon-studio/docs"
    ],
    "katalonGoldenImage": [
        "katalon-studio/katalon-golden-image(main)"
    ],
}

def retrieve_snyk_projects(snykOrgID, snykToken):
    # initialize variable snykProjects
    snykProjects = []
    nextLink = None

    url = f"https://api.snyk.io/rest/orgs/{snykOrgID}/projects?origins=github&version=2023-05-29&limit=100"
    headers = {
        "Accept": "application/vnd.api+json",
        "Authorization": f"{snykToken}"
    }
    response = requests.request("GET", url, headers=headers)
    data = response.json()['data']
    nextLink = response.json()['links']['next'] if 'next' in response.json()['links'].keys() else None
    #print(f"nextLink: {nextLink}")
    for snykProject in data:
        snykProjects.append(snykProject)
    while nextLink:
        url = f"https://api.snyk.io/rest{nextLink}"
        response = requests.request("GET", url, headers=headers)
        data = response.json()['data']
        nextLink = response.json()['links']['next'] if 'next' in response.json()['links'].keys() else None
        #print(f"nextLink: {nextLink}")
        for snykProject in data:
            snykProjects.append(snykProject)
    return snykProjects

def retrieve_repositories_from_snyk(snykOrgId=None, snykToken=None, snykProjects=None):
    if snykProjects is None:
        # retrieve Snyk projects
        snykProjects = retrieve_snyk_projects(snykOrgId, snykToken)

    # initialize variable repositories
    # repositories = {"productName": [repositoryName1, repositoryName2, ...]}
    repositories = {}
    for product in Products:
        repositories[product] = []
    repositories["Out-of-Scope"] = []

    # loop through snykProjects['projects']
    for snykProject in snykProjects:
        productname = None
        # get repository name
        repositoryName = snykProject['attributes']['name'].split(":")[0]
        # get project origin
        snykProjectOrigin = snykProject['attributes']['origin']
        # check if projectOrigin is "github"
        if snykProjectOrigin == "github":
            # check if repositoryName belongs to the Products dictionary
            for product in Products:
                if repositoryName in Products[product]:
                    productname = product
                    break
            if productname is None:
                productname = "Out-of-Scope"
            # check if repositoryName exists in repositories[product]
            if repositoryName not in repositories[productname]:
                # add repositoryName to repositories[product]
                repositories[productname].append(repositoryName)

    # print total number of repositories
    total = 0
    for product in repositories:
        total += len(repositories[product])
    print(f"Total number of repositories: {total}")

    # print repositories list of each product with each repository on a new line
    for product in repositories:
        print(f"Product: {product}")
        for repository in repositories[product]:
            print(f"\t{repository}")
    return repositories

def find_product_for_snyk_projects(snykProjects=None, snykOrgId=None, snykToken=None):
    if snykProjects is None:
        # retrieve Snyk projects
        snykProjects = retrieve_snyk_projects(snykOrgId, snykToken)

    # loop through snykProjects['projects']
    for snykProject in snykProjects:
        # get snykProjectId
        snykProjectId = snykProject['id']
        # get repository name
        repositoryName = snykProject['attributes']['name'].split(":")[0]

        productName, jiraProductId = find_product_for_snyk_project(snykProject=snykProject)
        print(f"snykProjectId: {snykProjectId}")
        print(f"repositoryName: {repositoryName}")
        print(f"productName: {productName}")
        
def retrieve_snyk_project(snykOrgId, snykProjectId, snykToken):
    url = f"https://api.snyk.io/rest/orgs/{snykOrgId}/projects/{snykProjectId}?version=2023-05-29"
    headers = {
        "Accept": "application/vnd.api+json",
        "Authorization": f"{snykToken}"
    }
    response = requests.request("GET", url, headers=headers)
    snykProject = response.json()['data']
    return snykProject

def find_product_for_snyk_project(snykProject=None, snykOrgId=None, snykProjectId=None, snykToken=None):
    if snykProject is None:
        # retrieve Snyk project
        snykProject = retrieve_snyk_project(snykOrgId, snykProjectId, snykToken)

    # get repository name
    repositoryName = snykProject['attributes']['name'].split(":")[0]

    # initialize variable
    productFound = False
    productName = None
    jiraProductId = None
    # check if repositoryName belongs to the Products dictionary
    for product in Products:
        if repositoryName in Products[product]:
            productFound = True
            productName = product
            break
    if productFound:
        if productName == "katalonStudio":
            jiraProductId = "11876"
        elif productName == "katalonTestOps":
            jiraProductId = "12314"
        elif productName == "katalonTestCloud":
            jiraProductId = "11878"
        elif productName == "katalonCloudStudio":
            jiraProductId = "11877"
        elif productName == "katalonOne":
            jiraProductId = "11883"
        elif productName == "katalonAI":
            jiraProductId = "11879"
        elif productName == "katalonIAM":
            jiraProductId = "12315"
        elif productName == "katalonWebsite":
            jiraProductId = "12288"
        elif productName == "katalonAcademy":
            jiraProductId = "12282"
        elif productName == "katalonGoldenImage":
            jiraProductId = "12596"
        else:
            productName = "katalonOther"
            jiraProductId = "12180"
    else:
        productName = "Out-of-Scope"
    
    return productName, jiraProductId


def retrieve_snyk_issues_from_snyk_project(snykOrgId, snykProjectId, snykToken):
    try:
        url = f"https://api.snyk.io/v1/org/{snykOrgId}/project/{snykProjectId}/aggregated-issues"
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"token {snykToken}"
        }
        data = json.dumps({
            "includeDescription": False,
            "includeIntroducedThrough": False
        })
        response = requests.request("POST", url, headers=headers, data=data)
        return response.json()
    except Exception as e:
        print(f"Error while retrieving Snyk issues from Snyk project {snykProjectId}: {e}")
        return None

def retrieve_jira_issues_from_snyk_project(snykOrgId, snykProjectId, snykToken):
    try:
        url = f"https://api.snyk.io/v1/org/{snykOrgId}/project/{snykProjectId}/jira-issues"
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"token {snykToken}"
        }
        response = requests.request("GET", url, headers=headers)
        return response.json()
    except Exception as e:
        print(f"Error while retrieving Jira issues from Snyk project {snykProjectId}: {e}")
        return None

def create_jira_issues_for_snyk_project(snykOrgId=None, snykProjectId=None, snykToken=None, snykProject=None, productName=None, jiraProductId=None):
    if snykProject is None:
        # retrieve Snyk project
        snykProject = retrieve_snyk_project(snykOrgId, snykProjectId, snykToken)
    else:
        # get snykProjectId from snykProject
        snykProjectId = snykProject['id']

    # get snykProjectType
    snykProjectType = snykProject['attributes']['type']

    # get snykProjectOrigin
    snykProjectOrigin = snykProject['attributes']['origin']

    # list Snyk issues on Snyk project
    snykIssues = retrieve_snyk_issues_from_snyk_project(snykOrgId, snykProjectId, snykToken)

    # list Jira issues on Snyk project
    jiraIssues = retrieve_jira_issues_from_snyk_project(snykOrgId, snykProjectId, snykToken)

    # find product for snykProject
    if productName is None and jiraProductId is None:
        productName, jiraProductId = find_product_for_snyk_project(snykProject=snykProject)

    # initialize variable for Snyk issues without Jira issues
    snykIssuesWithoutJiraIssues = []

    # check if Snyk issues is without Jira issues
    for snykIssue in snykIssues['issues']:
        # get snykIssueId and snykIssueType
        snykIssueId = snykIssue['id']
        snykIssueType = snykIssue['issueType']
        # check if snykIssueId is not in jiraIssues keys
        if snykIssueId not in jiraIssues.keys() and snykIssueType == "vuln":
            # add snykIssue to snykIssuesWithoutJiraIssues
            snykIssuesWithoutJiraIssues.append(snykIssue)
    
    # check if snykIssuesWithoutJiraIssues is not empty
    if snykIssuesWithoutJiraIssues:
        # print snykProjectId, snykProjectType, snykProjectOrigin, productName
        print("==================================================")
        print(f"snykProjectId: {snykProjectId}")
        print(f"snykProjectType: {snykProjectType}")
        print(f"snykProjectOrigin: {snykProjectOrigin}")
        print(f"productName: {productName}")
        print(f"Total number of Snyk issues without Jira issues: {len(snykIssuesWithoutJiraIssues)}")

        # Create Jira issues for Snyk issues without Jira issues
        for snykIssue in snykIssuesWithoutJiraIssues:
            # get snykIssueId
            snykIssueId = snykIssue['id']
            # check dry Run
            if args.dryRun:
                print(f"[dryRun] Creating Jira issue for Snyk issue {snykIssueId}")
            else:
                # get snykIssueTitle
                snykIssueTitle = snykIssue['issueData']['title']
                # get severity, cvssScore, CVSSv3, CVE, CWE, exploitMaturity from snykIssue['issueData']
                snykIssueSeverity = snykIssue['issueData']['severity']
                snykIssueCvssScore = snykIssue['issueData']['cvssScore']
                snykIssueCVSSv3 = snykIssue['issueData']['CVSSv3']
                snykIssueCVE = snykIssue['issueData']['identifiers']['CVE']
                snykIssueCWE = snykIssue['issueData']['identifiers']['CWE']
                snykIssueExploitMaturity = snykIssue['issueData']['exploitMaturity']

                ######### Create Jira issue for Snyk issue #########
                url = f"https://api.snyk.io/v1/org/{snykOrgId}/project/{snykProjectId}/issue/{snykIssueId}/jira-issue"
                headers = {
                    "Content-Type": "application/json",
                    "Authorization": f"token {snykToken}"
                }

                summary = f"{snykProject['attributes']['name']} - {snykIssue['issueData']['title']}"

                description = f"\r\n\\*\\* Issue details: \\*\\*\n\r\n severity:  {snykIssueSeverity}\n cvssScore:  {snykIssueCvssScore}\n CVSSv3:  {snykIssueCVSSv3}\n identifiers:  {snykIssueCVE} {snykIssueCWE}\n exploitMaturity:  {snykIssueExploitMaturity}\n\n\r\n\n[More about this issue on Snyk|https://app.snyk.io/org/katalon/project/{snykProjectId}#issue-{snykIssueId}]\n\n"

                if snykIssueSeverity == "critical":
                    vulnerabilitySeverity = "10202"
                    priority = "1"
                elif snykIssueSeverity == "high":
                    vulnerabilitySeverity = "10203"
                    priority = "2"
                elif snykIssueSeverity == "medium":
                    vulnerabilitySeverity = "10204"
                    priority = "3"
                elif snykIssueSeverity == "low":
                    vulnerabilitySeverity = "10205"
                    priority = "4"
                else:
                    vulnerabilitySeverity = "10206"
                    priority = "5"

                data = json.dumps({
                    "fields": {
                        "project": {
                            "key": "KVDP"
                        },
                        "summary": summary,
                        "description": description,
                        "issuetype": {
                            "name": "Vulnerability"
                        },
                        "customfield_10118": {
                            "id": vulnerabilitySeverity
                        },
                        "customfield_10695": str(snykIssueCvssScore),
                        "customfield_10697": {
                            "id": "11873"
                        },
                        "customfield_10698": {
                            "id": jiraProductId
                        },
                        "priority": {
                            "id": priority
                        }
                    }
                })
                print(f"Creating Jira issue for Snyk issue {snykIssueId}")
                response = requests.request("POST", url, headers=headers, data=data)
                if response.text:
                    try:
                        jiraIssueKey = response.json()[snykIssueId][0]['jiraIssue']['key']
                        print(f"Jira issue created: {jiraIssueKey}")
                    except Exception as e:
                        # print all error messages
                        print(f"Error while creating Jira issue: {type(e)} {e}")
                        print(f"Please check the response from Snyk api bellow:")
                        print(json.dumps(response.json(), indent=4))
                else:
                    print("Empty response")

def create_jira_issues(snykOrgId=None, snykToken=None, snykProjects=None):
    if snykProjects is None:
        # retrieve Snyk projects
        snykProjects = retrieve_snyk_projects(snykOrgId, snykToken)

    # loop through snykProjects['projects']
    for snykProject in snykProjects:
        productName, jiraProductId = find_product_for_snyk_project(snykProject=snykProject)
        # check if snykProject is in-scope by checking if productName is in Products.keys()
        if productName in Products.keys():
            # create Jira issues for in-scope snykProject
            create_jira_issues_for_snyk_project(snykOrgId=snykOrgId, snykToken=snykToken, snykProject=snykProject, productName=productName, jiraProductId=jiraProductId)
                

def update_jira_issues_for_snyk_project(snykOrgId=None, snykProjectId=None, snykToken=None, snykProject=None, jiraEmail=None, jiraToken=None):
    if snykProject is None:
        # retrieve Snyk project
        snykProject = retrieve_snyk_project(snykOrgId, snykProjectId, snykToken)
    else:
        # get snykProjectId from snykProject
        snykProjectId = snykProject['id']

    # retrieve Snyk issues on Snyk project
    snykIssues = retrieve_snyk_issues_from_snyk_project(snykOrgId, snykProjectId, snykToken)

    # retrieve Jira issues on Snyk project
    jiraIssues = retrieve_jira_issues_from_snyk_project(snykOrgId, snykProjectId, snykToken)

    # find product for snykProject
    productName, jiraProductId = find_product_for_snyk_project(snykProject=snykProject)

    for snykIssue in snykIssues['issues']:
        if snykIssue['id'] in jiraIssues.keys():
            jiraIssueKey = jiraIssues[snykIssue['id']][0]['jiraIssue']['key']

            url = f"https://katalon.atlassian.net/rest/api/3/issue/{jiraIssueKey}"
            auth = HTTPBasicAuth(jiraEmail, jiraToken)
            headers = {
                "Accept": "application/json",
                "Content-Type": "application/json",
            }

            # get severity, cvssScore, CVSSv3, CVE, CWE, exploitMaturity from snykIssue['issueData']
            snykIssueSeverity = snykIssue['issueData']['severity']
            snykIssueCvssScore = snykIssue['issueData']['cvssScore']
            snykIssueCVSSv3 = snykIssue['issueData']['CVSSv3']
            snykIssueCVE = snykIssue['issueData']['identifiers']['CVE']
            snykIssueCWE = snykIssue['issueData']['identifiers']['CWE']
            snykIssueExploitMaturity = snykIssue['issueData']['exploitMaturity']

            summary = f"{snykProject['attributes']['name']} - {snykIssue['issueData']['title']}"

            if snykIssueSeverity == "critical":
                vulnerabilitySeverity = "10202"
                priority = "1"
            elif snykIssueSeverity == "high":
                vulnerabilitySeverity = "10203"
                priority = "2"
            elif snykIssueSeverity == "medium":
                vulnerabilitySeverity = "10204"
                priority = "3"
            elif snykIssueSeverity == "low":
                vulnerabilitySeverity = "10205"
                priority = "4"
            else:
                vulnerabilitySeverity = "10206"
                priority = "5"

            data = json.dumps({
                "fields": {
                    "summary": summary,
                    "description": {
                        "version": 1,
                        "type": "doc",
                        "content": [
                            {
                                "type": "paragraph",
                                "content": [
                                    {
                                        "type": "text",
                                        "text": "** Issue details: **"
                                    }
                                ]
                            },
                            {
                                "type": "paragraph",
                                "content": [
                                    {
                                        "type": "text",
                                        "text": f"severity:  {snykIssueSeverity}"
                                    },
                                    {
                                        "type": "hardBreak"
                                    },
                                    {
                                        "type": "text",
                                        "text": f"cvssScore:  {snykIssueCvssScore}"
                                    },
                                    {
                                        "type": "hardBreak"
                                    },
                                    {
                                        "type": "text",
                                        "text": f"CVSSv3:  {snykIssueCVSSv3}"
                                    },
                                    {
                                        "type": "hardBreak"
                                    },
                                    {
                                        "type": "text",
                                        "text": f"identifiers:  {snykIssueCVE} {snykIssueCWE}"
                                    },
                                    {
                                        "type": "hardBreak"
                                    },
                                    {
                                        "type": "text",
                                        "text": f"exploitMaturity:  {snykIssueExploitMaturity}"
                                    }
                                ]
                            },
                            {
                                "type": "paragraph",
                                "content": [
                                    {
                                        "type": "text",
                                        "text": "More about this issue on Snyk",
                                        "marks": [
                                            {
                                                "type": "link",
                                                "attrs": {
                                                    "href": f"https://app.snyk.io/org/katalon/project/{snykProjectId}#issue-{snykIssue['id']}"
                                                }
                                            }
                                        ]
                                    }
                                ]
                            }
                        ]
                    },
                    "customfield_10118": {
                        "id": vulnerabilitySeverity
                    },
                    "customfield_10695": str(snykIssueCvssScore),
                    "customfield_10697": {
                        "id": "11873"
                    },
                    "customfield_10698": {
                        "id": jiraProductId
                    },
                    "priority": {
                        "id": priority
                    }
                }
            })

            response = requests.request("PUT", url, headers=headers, data=data, auth=auth)
            if response.text:
                print(json.dumps(response.json(), indent=4))
            else:
                print("Empty response")

def update_jira_issues(snykOrgId=None, snykToken=None, snykProjects=None, jiraEmail=None, jiraToken=None):
    if snykProjects is None:
        # retrieve Snyk projects
        snykProjects = retrieve_snyk_projects(snykOrgId, snykToken)

    # loop through snykProjects['projects']
    for snykProject in snykProjects:
        if productName in Products.keys():
            # update Jira issues
            update_jira_issues_for_snyk_project(snykOrgId=snykOrgId, snykToken=snykToken, snykProject=snykProject, jiraEmail=jiraEmail, jiraToken=jiraToken)

def retrieve_jira_issue(jiraIssueKey, jiraEmail, jiraToken):
    url = f"https://katalon.atlassian.net/rest/api/3/issue/{jiraIssueKey}"
    auth = HTTPBasicAuth(jiraEmail, jiraToken)
    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json",
    }
    response = requests.request("GET", url, headers=headers, auth=auth)
    return response.json()

def find_open_jira_issues(jiraEmail=None, jiraToken=None, productName=None):
    url = "https://katalon.atlassian.net/rest/api/3/search"
    auth = HTTPBasicAuth(jiraEmail, jiraToken)
    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json",
    }

    if productName is None:
        jql = "project = KVDP AND issuetype = Vulnerability AND 'Vulnerability Source[Dropdown]' = Snyk AND status IN ('TO DO', Triaging, Verified, Develop, 'Ready for Review')"
    else:
        jql = f"project = KVDP AND issuetype = Vulnerability AND 'Vulnerability Source[Dropdown]' = Snyk AND status IN ('TO DO', Triaging, Verified, Develop, 'Ready for Review') AND Product = '{productName}'"

    data = json.dumps({
        "jql": jql,
        "maxResults": 1,
        "startAt": 0
    })
    response = requests.request("POST", url, headers=headers, data=data, auth=auth)

    if response.text:
        try:
            total = response.json()['total']
            print(f"Total number of open Jira issues: {total}")
        except Exception as e:
            # print all error messages
            print(f"Error while getting total number of open Jira issues: {type(e)} {e}")
            print(f"Please check the response from Snyk api bellow:")
            print(json.dumps(response.json(), indent=4))

    openJiraIssues = []

    for i in range(0, total, 100):
        data = json.dumps({
            "jql": jql,
            "maxResults": 100,
            "startAt": i
        })
        response = requests.request("POST", url, headers=headers, data=data, auth=auth)
        for issue in response.json()['issues']:
            openJiraIssues.append(issue)
            #print(issue['key'])
    return openJiraIssues

def close_jira_issue(jiraIssueKey, jiraEmail, jiraToken):
    # retrieve Jira issue
    jiraIssue = retrieve_jira_issue(jiraIssueKey, jiraEmail, jiraToken)
    # extract "description" content from jiraIssue then find paragraph in "content" of "description" that contains "More about this issue on Snyk"
    jiraIssueDescriptionContent = jiraIssue['fields']['description']['content']
    # try to extract snykIssueUrl from jiraIssueDescriptionContent
    snykIssueUrl = None

    try:
        matchings = [matching for matching in jiraIssueDescriptionContent if "More about this issue on Snyk" in matching['content'][0]['text']]
        first_matching = matchings[0] if matchings else None
        if first_matching:
            snykIssueUrl = first_matching['content'][0]['marks'][0]['attrs']['href']
        else:
            matching_old_1s = [matching_old_1 for matching_old_1 in jiraIssueDescriptionContent if "See this issue on Snyk" in matching_old_1['content'][0]['text']]
            first_matching_old_1 = matching_old_1s[0] if matching_old_1s else None
            if first_matching_old_1:
                matching_old_2s = [matching_old_2 for matching_old_2 in jiraIssueDescriptionContent if "More About this issue" in matching_old_2['content'][0]['text']]
                first_matching_old_2 = matching_old_2s[0] if matching_old_2s else None
                if first_matching_old_2:
                    snykProjectId = first_matching_old_1['content'][0]['marks'][0]['attrs']['href'].split("/")[6]
                    snykIssueId = first_matching_old_2['content'][0]['marks'][0]['attrs']['href'].split("/")[4]
                    snykIssueUrl = f"https://app.snyk.io/org/katalon/project/{snykProjectId}#issue-{snykIssueId}"
    except Exception as e:
        print(f"Error while trying to find Snyk issue URL: {e}")
        print(f"Can not find Snyk issue URL in Jira issue {jiraIssueKey}")

    # check if snykIssueUrl exists in jiraIssueDescriptionContent
    if snykIssueUrl:
        print(f"Found Snyk issue URL {snykIssueUrl} in Jira issue {jiraIssueKey}")
        # extract snykProjectId from snykIssueUrl
        snykProjectId = snykIssueUrl.split("/")[6].split("#issue-")[0]
        # extract snykIssueId from snykIssueUrl
        snykIssueId = snykIssueUrl.split("#issue-")[1]
        # list snykIssues on snykProject
        snykIssues = retrieve_snyk_issues_from_snyk_project(args.snykOrgId, snykProjectId, args.snykToken)
        # check if snykIssueId exists in snykIssues
        snykIssueIdExists = False
        for snykIssue in snykIssues['issues']:
            if snykIssue['id'] == snykIssueId:
                snykIssueIdExists = True
                break
        if snykIssueIdExists:
            print(f"Snyk issue {snykIssueId} exists on Snyk project {snykProjectId}")
        else:
            print(f"Snyk issue {snykIssueId} does not exist on Snyk project {snykProjectId}")
            # close Jira issue by editing Jira issue status to "Mitigated"
            # https://stackoverflow.com/questions/73789285/how-to-update-the-status-on-a-jira-issue-vis-jira-rest-api
            url = f"https://katalon.atlassian.net/rest/api/3/issue/{jiraIssueKey}/transitions"
            auth = HTTPBasicAuth(jiraEmail, jiraToken)
            headers = {
                "Accept": "application/json",
                "Content-Type": "application/json",
            }
            data = json.dumps({
                "transition": {
                    "id": "91"
                }
            })
            response = requests.request("POST", url, headers=headers, data=data, auth=auth)
            if response.text:
                print(json.dumps(response.json(), indent=4))
            else:
                print("Empty response")

def close_jira_issues(openJiraIssues=None, jiraEmail=None, jiraToken=None, productName=None):
    if openJiraIssues is None:
        # find open Jira issues
        if productName is None:
            openJiraIssues = find_open_jira_issues(jiraEmail=jiraEmail, jiraToken=jiraToken)
        else:
            openJiraIssues = find_open_jira_issues(jiraEmail=jiraEmail, jiraToken=jiraToken, productName=productName)

    # initialize snykIssueIds dictionary
    # snykIssueIds = {"snykProjectId": [snykIssueId1, snykIssueId2, ...]}
    snykIssueIds = {}

    # loop through openJiraIssues
    for openJiraIssue in openJiraIssues:
        # extract openJiraIssueKey from openJiraIssue
        openJiraIssueKey = openJiraIssue['key']
        # extract "description" content from jiraIssue then find paragraph in "content" of "description" that contains "More about this issue on Snyk"
        openJiraIssueDescriptionContent = openJiraIssue['fields']['description']['content']
        # try to extract snykIssueUrl from jiraIssueDescriptionContent
        snykIssueUrl = None
        try:
            matchings = [matching for matching in openJiraIssueDescriptionContent if "More about this issue on Snyk" in matching['content'][0]['text']]
            first_matching = matchings[0] if matchings else None
            if first_matching:
                snykIssueUrl = first_matching['content'][0]['marks'][0]['attrs']['href']
            else:
                matching_old_1s = [matching_old_1 for matching_old_1 in openJiraIssueDescriptionContent if "See this issue on Snyk" in matching_old_1['content'][0]['text']]
                first_matching_old_1 = matching_old_1s[0] if matching_old_1s else None
                if first_matching_old_1:
                    matching_old_2s = [matching_old_2 for matching_old_2 in openJiraIssueDescriptionContent if "More About this issue" in matching_old_2['content'][0]['text']]
                    first_matching_old_2 = matching_old_2s[0] if matching_old_2s else None
                    if first_matching_old_2:
                        snykProjectId = first_matching_old_1['content'][0]['marks'][0]['attrs']['href'].split("/")[6]
                        snykIssueId = first_matching_old_2['content'][0]['marks'][0]['attrs']['href'].split("/")[4]
                        snykIssueUrl = f"https://app.snyk.io/org/katalon/project/{snykProjectId}#issue-{snykIssueId}"
        except Exception as e:
            # do nothing
            pass
            #print(f"Error while trying to find Snyk issue URL: {e}")
            #print(f"Can not find Snyk issue URL in Jira issue {openJiraIssueKey}")

        # check if snykIssueUrl is extracted
        if snykIssueUrl:
            #print(f"[+] Found Snyk issue URL {snykIssueUrl} in Jira issue {openJiraIssueKey}")
            # extract snykProjectId from snykIssueUrl
            snykProjectId = snykIssueUrl.split("/")[6].split("#issue-")[0]
            # extract snykIssueId from snykIssueUrl
            snykIssueId = snykIssueUrl.split("#issue-")[1]
            # check if snykProjectId exists in snykIssueIds keys
            if snykProjectId not in snykIssueIds.keys():
                try:
                    # list snykIssues on snykProject
                    snykIssues = retrieve_snyk_issues_from_snyk_project(args.snykOrgId, snykProjectId, args.snykToken)
                    # initialize snykIssueIds[snykProjectId]
                    snykIssueIds[snykProjectId] = []
                    # loop through snykIssues['issues'] to add snykIssueId to snykIssueIds[snykProjectId]
                
                    for snykIssue in snykIssues['issues']:
                        snykIssueIds[snykProjectId].append(snykIssue['id'])
                except Exception as e:
                    print(f"Error while getting snykIssues from openJiraIssue: {openJiraIssue} snykOrgId: {args.snykOrgId} snykProjectId: {snykProjectId}: {e}")
                    print(f"Please check the response from Snyk api bellow:")
                    print(json.dumps(snykIssues, indent=4))

            # check if snykIssueId exists in snykIssues
            if snykIssueId not in snykIssueIds[snykProjectId]:
                if args.dryRun:
                    print(f"[dryRun] Closing Jira issue {openJiraIssueKey} for {snykIssueUrl}")
                else:
                    print(f"[+] Closing Jira issue {openJiraIssueKey} for {snykIssueUrl}")
                    # close Jira issue by editing Jira issue status to "Mitigated"
                    url = f"https://katalon.atlassian.net/rest/api/3/issue/{openJiraIssueKey}/transitions"
                    auth = HTTPBasicAuth(jiraEmail, jiraToken)
                    headers = {
                        "Accept": "application/json",
                        "Content-Type": "application/json",
                    }
                    data = json.dumps({
                        "transition": {
                            "id": "91"
                        }
                    })
                    response = requests.request("POST", url, headers=headers, data=data, auth=auth)
                    if response.text:
                        print(json.dumps(response.json(), indent=4))
                    else:
                        print("Empty response")
            # else:
            #     print(f"[+] {snykIssueUrl}")

def main():
    if args.function:
        function_name = args.function
        # Define a dictionary mapping function names to functions
        functions = {
            # Add all functions here
            'retrieve_snyk_projects': retrieve_snyk_projects,
            'retrieve_repositories_from_snyk': retrieve_repositories_from_snyk,
            'find_product_for_snyk_projects': find_product_for_snyk_projects,
            'retrieve_snyk_project': retrieve_snyk_project,
            'find_product_for_snyk_project': find_product_for_snyk_project,
            'retrieve_snyk_issues_from_snyk_project': retrieve_snyk_issues_from_snyk_project,
            'retrieve_jira_issues_from_snyk_project': retrieve_jira_issues_from_snyk_project,
            'create_jira_issues_for_snyk_project': create_jira_issues_for_snyk_project,
            'create_jira_issues': create_jira_issues,
            'update_jira_issues_for_snyk_project': update_jira_issues_for_snyk_project,
            'update_jira_issues': update_jira_issues,
            'retrieve_jira_issue': retrieve_jira_issue,
            'find_open_jira_issues': find_open_jira_issues,
            'close_jira_issue': close_jira_issue,
            'close_jira_issues': close_jira_issues
        }
        # Check if the function exists in the dictionary
        if function_name in functions:
            # Call the function with the appropriate arguments
            if function_name == 'retrieve_snyk_projects':
                print(json.dumps(functions[function_name](args.snykOrgId, args.snykToken), indent=4))
            elif function_name == 'retrieve_repositories_from_snyk':
                functions[function_name](snykOrgId=args.snykOrgId, snykToken=args.snykToken)
            elif function_name == 'find_product_for_snyk_projects':
                functions[function_name](snykOrgId=args.snykOrgId, snykToken=args.snykToken)
            elif function_name == 'retrieve_snyk_project':
                print(json.dumps(functions[function_name](args.snykOrgId, args.snykProjectId, args.snykToken), indent=4))
            elif function_name == 'find_product_for_snyk_project':
                print(functions[function_name](snykOrgId=args.snykOrgId, snykProjectId=args.snykProjectId, snykToken=args.snykToken))
            elif function_name == 'retrieve_snyk_issues_from_snyk_project':
                print(json.dumps(functions[function_name](args.snykOrgId, args.snykProjectId, args.snykToken), indent=4))
            elif function_name == 'retrieve_jira_issues_from_snyk_project':
                print(json.dumps(functions[function_name](args.snykOrgId, args.snykProjectId, args.snykToken), indent=4))
            elif function_name == 'create_jira_issues_for_snyk_project':
                functions[function_name](snykOrgId=args.snykOrgId, snykProjectId=args.snykProjectId, snykToken=args.snykToken)
            elif function_name == 'create_jira_issues':
                functions[function_name](snykOrgId=args.snykOrgId, snykToken=args.snykToken)
            elif function_name == 'update_jira_issues_for_snyk_project':
                functions[function_name](snykOrgId=args.snykOrgId, snykProjectId=args.snykProjectId, snykToken=args.snykToken, jiraEmail=args.jiraEmail, jiraToken=args.jiraToken)
            elif function_name == 'update_jira_issues':
                functions[function_name](snykOrgId=args.snykOrgId, snykToken=args.snykToken, jiraEmail=args.jiraEmail, jiraToken=args.jiraToken)
            elif function_name == 'retrieve_jira_issue':
                print(json.dumps(functions[function_name](args.jiraIssueKey, args.jiraEmail, args.jiraToken), indent=4))
            elif function_name == 'find_open_jira_issues':
                if args.productName:
                    print(json.dumps(functions[function_name](jiraEmail=args.jiraEmail, jiraToken=args.jiraToken, productName=args.productName), indent=4))
                else:
                    print(json.dumps(functions[function_name](jiraEmail=args.jiraEmail, jiraToken=args.jiraToken), indent=4))
            elif function_name == 'close_jira_issue':
                functions[function_name](args.jiraIssueKey, args.jiraEmail, args.jiraToken)
            elif function_name == 'close_jira_issues':
                if args.productName:
                    functions[function_name](jiraEmail=args.jiraEmail, jiraToken=args.jiraToken, productName=args.productName)
                else:
                    functions[function_name](jiraEmail=args.jiraEmail, jiraToken=args.jiraToken)
        else:
            print(f"Function {function_name} does not exist")
    else:
        print("No function is specified, run create_jira_issues function by default")
        create_jira_issues(snykOrgId=args.snykOrgId, snykToken=args.snykToken)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="This script is used to sync issues between Snyk and Jira")
    parser.add_argument("--jiraEmail", help="The email address associated with the Jira account.")
    parser.add_argument("--jiraToken", help="The API token for the Jira account.")
    parser.add_argument("--jiraIssueKey", help="The key of the Jira issue to be updated.")
    parser.add_argument("--snykToken", help="The API token for the Snyk account.")
    parser.add_argument("--snykOrgId", help="The ID of the Snyk organization.")
    parser.add_argument("--snykProjectId", help="The ID of the Snyk project.")
    # --productName is the name displayed on Jira, for example: --productName "Katalon Studio"
    parser.add_argument("-P", "--productName", help="The name of the product displayed on Jira.")
    parser.add_argument("-F", "--function", help="The function to be executed.")
    parser.add_argument("--dryRun", action='store_true', help="Run the script without making any changes.")
    args = parser.parse_args()

    main()
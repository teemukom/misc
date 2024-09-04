<#
.SYNOPSIS
    Creates required resources for deploying Application Landing Zone components from Azure Devops.
    Resources created:
    - Resource Group
    - User Assigned Identity
    - Role Assignments at Subscription level
        - Contributor
        - User Access Administrator
            - Write/Delete for Owner, Role Based Access Control Administrator and User Access Administrator roles excluded
    - Federated Identity Credentials
    - Service Connection
.DESCRIPTION
    Requirements
    - User Access Administrator or Owner role to the target Subscription
    - Personal Access Token (PAT) to the target ADO Organization with scope:
        - Service Connections
            - Read, query, & manage

.PARAMETER AzureDevOpsOrganisationName
    Azure Devops Organization name where the Service Connection will be created.

.PARAMETER AzureDevOpsProjectName
    Azure Devops Project name where the Service Connection will be created.

.PARAMETER SubscriptionId
    The Landing Zone subscription Id where resources are being deployed and which the Service Connection will have access to.

.PARAMETER LandingzoneName
    The Landing Zone name. Value must be greater than 5 characters and less than 100 characters.

.PARAMETER Environment
    Environment type. Valid values are 'dev', 'test' and 'prod'.

.EXAMPLE
    .\Create-ServiceConnection.ps1 -AzureDevOpsOrganisationName contoso -AzureDevOpsProjectName landingzones -SubscriptionId 11111111-2222-3333-4444-555555555555 -LandingzoneName application1 -Environment dev

    Creates the Service Connection to Azure Devops Organization 'contoso' to Project 'landingzones'. Azure Resources will be created to subscription '11111111-2222-3333-4444-555555555555'.
#>

param (
        [Parameter(Mandatory=$true)]
        [string] $AzureDevOpsOrganisationName,

        [Parameter(Mandatory=$true)]
        [string] $AzureDevOpsProjectName,

        [Parameter(Mandatory=$true)]
        [string] $SubscriptionId,

        [Parameter(Mandatory=$true)]
        [ValidateLength(5,100)]
        [string] $LandingzoneName,

        [Parameter(Mandatory=$true)]
        [ValidateSet("dev","test", "prod")]
        [string] $Environment,

        [Parameter(Mandatory=$true)]
        [string] $PAT

      )

# Variables
$ResourceGroupName = 'rg-identity'
$Location = 'westeurope'
$AzureDevOpsAuthenicationHeader = @{Authorization = 'Basic ' + [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes(":$($PAT)")) }

$ManagedIdentityName = 'id-'+$Environment+'-lz-'+$LandingzoneName

$ServiceConnectionName = 'sc-id-'+$Environment+'-lz-'+$LandingzoneName

$FederatedIdentityName = 'federatedIdentityCredentialsAzureDevOps'

$Scope = '/subscriptions/'+$SubscriptionId

# Condition for User Access Administrator role assignment
# Prevents creation/deletion for Owner, Role Based Access Control Administrator and User Access Administrator roles
$UserAccessAdminCondition = "
(
 (
  !(ActionMatches{'Microsoft.Authorization/roleAssignments/write'})
 )
 OR 
 (
  @Request[Microsoft.Authorization/roleAssignments:RoleDefinitionId] ForAnyOfAllValues:GuidNotEquals {8e3af657-a8ff-443c-a75c-2fe8c4bcb635, 18d7d88d-d35e-4fb5-a5c3-7773c20a72d9, f58310d9-a9f6-439a-9e8d-f62e7b41a168}
 )
)
AND
(
 (
  !(ActionMatches{'Microsoft.Authorization/roleAssignments/delete'})
 )
 OR 
 (
  @Resource[Microsoft.Authorization/roleAssignments:RoleDefinitionId] ForAnyOfAllValues:GuidNotEquals {8e3af657-a8ff-443c-a75c-2fe8c4bcb635, 18d7d88d-d35e-4fb5-a5c3-7773c20a72d9, f58310d9-a9f6-439a-9e8d-f62e7b41a168}
 )
)
"
$ConditionVersion = "2.0"

# Flush variables
$issuer = ''
$subjectIdentifier = ''

# Output a summary of user input
Write-Host "Provided values" -ForegroundColor Blue
Write-Host "Azure DevOps Organisation Name: " -NoNewLine -ForegroundColor Yellow
Write-Host $AzureDevOpsOrganisationName
Write-Host "Azure DevOps Project Name: " -NoNewLine -ForegroundColor Yellow
Write-Host $AzureDevOpsProjectName
Write-Host "Subscription Id: " -NoNewLine -ForegroundColor Yellow
Write-Host $SubscriptionId
Write-Host "Landing Zone Name: " -NoNewLine -ForegroundColor Yellow
Write-Host $LandingzoneName
Write-Host "Environment: "  -NoNewLine -ForegroundColor Yellow
Write-Host $Environment
Write-Host ""
Write-Host "With these values the following resources are being created:" -ForegroundColor Blue
Write-Host "User assigned identity: " -NoNewLine -ForegroundColor Yellow
Write-Host $ManagedIdentityName
Write-Host "Federated Identity Credentials: " -NoNewLine -ForegroundColor Yellow
Write-Host "Issuer=https://vstoken.dev.azure.com/<Organization Id>, Subject Identifier=sc://$AzureDevOpsOrganisationName/$AzureDevOpsProjectName/$ServiceConnectionName"
Write-Host "Role assignment: " -NoNewLine -ForegroundColor Yellow
Write-Host "Contributor and User Access Administrator roles for $ManagedIdentityName to $Scope"
Write-Host "Service Connection: " -NoNewLine -ForegroundColor Yellow
Write-Host $ServiceConnectionName
Write-Host ""
Write-Warning "Check values above and Confirm (Y) or Exit (S)" -WarningAction Inquire
Write-Host ""
Write-Host ""

try {
    # Check if we can switch to the subscription selected
    if(!(Set-AzContext -Subscription $SubscriptionId -ErrorAction SilentlyContinue)) {
        Write-Host "ERROR: Unable to switch to subscription $subscriptionId. Please provide a valid subscriptionId." -ForegroundColor Red
        exit

    }
    else {
        $currentSubscription = Get-AzContext
        Write-Host "Current subscription is $($currentSubscription.Subscription.Name) $($currentSubscription.Subscription.Id)"
        $SubscriptionName = (Get-AzSubscription -SubscriptionId $SubscriptionId).Name
    }
    
    # Retrieving Azure DevOps Organisation ID
    $restApiAdoOrgInfo = "https://dev.azure.com/$AzureDevOpsOrganisationName/_apis/connectiondata?api-version=5.0-preview.1"
    $azureDevOpsOrganisationId = Invoke-RestMethod -Uri $restApiAdoOrgInfo -Headers $AzureDevOpsAuthenicationHeader -Method Get | Select-Object -ExpandProperty instanceId

    # Retrieve Azure DevOps Project ID
    $restApiAdoProjectInfo = "https://dev.azure.com/$AzureDevOpsOrganisationName/_apis/projects/$($AzureDevOpsProjectName)?api-version=7.1-preview.4"
    $azureDevOpsProjectId = Invoke-RestMethod -Uri $restApiAdoProjectInfo -Headers $AzureDevOpsAuthenicationHeader -Method Get | Select-Object -ExpandProperty id

    # OIDC information needed for User Assigned Managed Identity
    $issuer = "https://vstoken.dev.azure.com/$azureDevOpsOrganisationId"
    $subjectIdentifier = "sc://$AzureDevOpsOrganisationName/$AzureDevOpsProjectName/$ServiceConnectionName"

    # Create Resource Group if it doesn't exist
    if(!(Get-AzResourceGroup -Name $ResourceGroupName -Location $Location -ErrorAction SilentlyContinue)) {
        Write-Host "Creating Resource Group $ResourceGroupName to $Location " -ForegroundColor Green
        New-AzResourceGroup -Name $ResourceGroupName -Location $Location | Out-Null
    }
    else {
        Write-Host "Resource Group $ResourceGroupName at $Location already exists." -ForegroundColor Yellow
    }

    # Create User Assigned Identity if it doesn't exist
    if(!(Get-AzUserAssignedIdentity -ResourceGroupName $ResourceGroupName -Name $ManagedIdentityName -ErrorAction SilentlyContinue)) {
        Write-Host "Creating User Assigned Identity $ManagedIdentityName to $ResourceGroupName at $Location " -ForegroundColor Green
        New-AzUserAssignedIdentity -Location $Location -ResourceGroupName $ResourceGroupName -Name $ManagedIdentityName | Out-Null
        Write-Host "Waiting 20 seconds for replication..."
        Start-Sleep -Seconds 20
    }
    else {
        Write-Host "User Assigned Identity $ManagedIdentityName in $ResourceGroupName at $Location already exists" -ForegroundColor Yellow
    }

    # Gather required parameters from the User Assigned Identity
    $clientId = (Get-AzUserAssignedIdentity -Name $ManagedIdentityName -ResourceGroupName $ResourceGroupName).ClientId
    $tenantId = (Get-AzUserAssignedIdentity -Name $ManagedIdentityName -ResourceGroupName $ResourceGroupName).TenantId
    $principalId = (Get-AzUserAssignedIdentity -Name $ManagedIdentityName -ResourceGroupName $ResourceGroupName).PrincipalId

    # Create Role Assignments if they don't exist
    # Contributor
    if(Get-AzRoleAssignment -ObjectId $principalId -Scope $Scope -RoleDefinitionName 'Contributor') {
            Write-Host "Contributor role assignment for $principalId at scope $Scope already exists" -ForegroundColor Yellow
    }
    else {
        New-AzRoleAssignment -ObjectId $principalId -Scope $Scope -RoleDefinitionName 'Contributor' | Out-Null
        Write-Host "New Contributor role assignment created to scope $scope for $principalId" -ForegroundColor Green
    }

    # User Access administrator with conditions
    if(Get-AzRoleAssignment -ObjectId $principalId -Scope $Scope -RoleDefinitionName 'User Access Administrator') {
        Write-Host "User Access Administrator role assignment for $principalId at scope $Scope already exists" -ForegroundColor Yellow
    }
    else {
        New-AzRoleAssignment -ObjectId $principalId -Scope $Scope -RoleDefinitionName 'User Access Administrator' -Condition $UserAccessAdminCondition -ConditionVersion $ConditionVersion| Out-Null
        Write-Host "New User Access Administrator role assignment created to scope $scope for $principalId" -ForegroundColor Green
    }
    
    # Create Federated Identity Credentials if it doesn't exist
    if(!(Get-AzFederatedIdentityCredentials -ResourceGroupName $ResourceGroupName -IdentityName $ManagedIdentityName -Name $FederatedIdentityName -ErrorAction SilentlyContinue)) {
        Write-Host "Creating Federated Identity Credential for $ManagedIdentityName with issuer $issuer and subject $subjectIdentifier" -ForegroundColor Green
        New-AzFederatedIdentityCredentials -ResourceGroupName $ResourceGroupName -IdentityName $ManagedIdentityName -Name $FederatedIdentityName -Issuer $issuer -Subject $subjectIdentifier -Audience 'api://AzureADTokenExchange' | Out-Null
    }
    else {
        Write-Host "Federated Identity Credential for $ManagedIdentityName with issuer $issuer and subject $subjectIdentifier already exists" -ForegroundColor Yellow
    }

    # Populate ADO Endpoint URL and check if the Service Connection already exists.
    $getServiceConnectionEndpointUrl = "https://dev.azure.com/$AzureDevOpsOrganisationName/$AzureDevOpsProjectName/_apis/serviceendpoint/endpoints?api-version=7.1-preview.4"
    $existing = Invoke-RestMethod -Uri $getServiceConnectionEndpointUrl -Headers $AzureDevOpsAuthenicationHeader -Method Get | Select-Object -ExpandProperty value | Where-Object { $_.name -eq $ServiceConnectionName } | Select-Object -ExpandProperty id

    if($existing) {
        Write-Host "Service Connection ($ServiceConnectionName) already exists." -ForegroundColor Yellow
    }

    # Create a new one if doesn't.
    else {
    $body = @"
      {
          "authorization": {
              "parameters": {
                  "serviceprincipalid": "$clientId",
                  "tenantid": "$tenantId"
              },
              "scheme": "WorkloadIdentityFederation"
          },
          "createdBy": {},
          "data": {
              "environment": "AzureCloud",
              "scopeLevel": "Subscription",
              "creationMode": "Manual",
              "subscriptionId": "$SubscriptionId",
              "subscriptionName": "$SubscriptionName"
          },
          "isShared": false,
          "isOutdated": false,
          "isReady": false,
          "name": "$ServiceConnectionName",
          "owner": "library",
          "type": "AzureRM",
          "url": "https://management.azure.com/",
          "description": "",
          "serviceEndpointProjectReferences": [
              {
                  "description": "Service connection to Landing Zone $SubscriptionName",
                  "name": "$ServiceConnectionName",
                  "projectReference": {
                      "id": "$azureDevOpsProjectId",
                      "name": "$AzureDevOpsProjectName"
                  }
              }
          ]
      }
"@

# Registering OIDC service connection
$restApiEndpointUrl = "https://dev.azure.com/$AzureDevOpsOrganisationName/_apis/serviceendpoint/endpoints?api-version=7.1-preview.4"
$serviceConnection = Invoke-RestMethod -Uri $restApiEndpointUrl -Headers $AzureDevOpsAuthenicationHeader -Method Post -Body $body -ContentType 'application/json'
Write-Host "Service Connection $serviceConnectionName created to project $AzureDevopsProjectName" -ForegroundColor Green
}

}
catch {
    Write-host -f red "Encountered Error:"$_.Exception.Message
}

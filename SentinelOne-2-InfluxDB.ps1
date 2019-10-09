Import-Module Influx
$T = 1

Do{

$Global:ExecuteTime = Get-date
$Global:CurrentRunTimeStamp = Get-TimeStamp $Global:ExecuteTime
$Global:apiKey = "Insert API Token Key"
$Global:InfluxServer = "Insert URL for Influx DB Server"
$Global:InfluxDB = "Insert Database Name"
$global:SkipValue = 100
$Global:Tenant = "Insert SentinelOne Tenant"


#Create the current timestamp
function Get-TimeStamp ($a) {
    
    return "{0:MM-dd-yy} {0:HH:mm:ss}" -f ($a)
    
}

function Read-LastRun {
    $Global:LastRun = Get-Content .\SentinelOneTimeStamp.txt | Select -Last 1
    $Global:LastRunTimeStamp = Get-TimeStamp $Global:LastRun
}

function Get_ThreatByClassification
{
$URL = "https://$Global:Tenant.sentinelone.net/web/api/v2.0/private/threats/filters-count?apiToken=$Global:apiKey"
$web1 = Invoke-RestMethod -uri $URL
$temp = $web1.data
$metrics = $temp | Where-Object title -Contains Classification


 foreach ($i in $metrics.values)
    {
        #$NameContat = $i.name.Trim("\")
        #$nameContat
        $ThreatCount = ""
        $ThreatTitle = ""
        $ThreatCount = $i.Count
        $ThreatTitle = $i.Title       

        $InputMetric = @{
            Title = "$ThreatTitle"
            Count = "$ThreatCount"
        }

        Write-Influx -Measure ThreatsClassification -Tags @{Site="Canada"} -Metrics $InputMetric -Database SentinelOne -Server http://192.168.250.151:8086 -Verbose
    }
 
    }


#Get Threats in sentinel one by Computer with the creation date
function Get_ActiveThreatByAgent
{
$StartTime = Get-TimeStamp (Get-Date)
"Start --- $StartTime" | Out-file .\SentinelOneTimelog.txt -Append

Read-LastRun
$Global:LastRunTimeStamp
[datetime]$lastrun = $Global:LastRunTimeStamp
$Exe_Date = $lastRun.ToString("yyyy-MM-dd" )
$Exe_Hours = $lastRun.ToString("HH")
$Exe_Minute = $lastRun.ToString("mm")
$Exe_Seconde = $lastRun.ToString("ss")
$Skip = ""


$URL = "https://usea1-008.sentinelone.net/web/api/v2.0/threats?skipCount=True&countOnly=false&limit=100&createdAt__gt=$Exe_Date" + "T$EXE_Hours" + "%3A$EXE_Minute" + "%3A$EXE_Seconde.0Z&apiToken=$Global:apiKey"



Try {


$web1 = Invoke-RestMethod -uri $URL
$CountWebItem = $web1.data | Measure-Object threatName
$PageCount = 0

DO{
$metrics = $web1.data

 foreach ($i in $metrics)
    {
        $SiteName = $i.SiteName
        $assettemp = $i.agentComputerName
        $AssetName = $i.agentComputerName
        $ThreatName = $i.threatName
        $Classification = $i.classification
        $mitigationMode = $I.mitigationMode
        $createdDate = $i.createdDate
        $Resolved = $i.Resolved
        $Rank = $i.rank
        $AgentOS = $i.agentOsType
        $engines = $i.engines
        $username = $i.username

        $InputMetric = @{
            ThreatName = "$ThreatName"
        }

        $tag = @{
                    Site = $SiteName
                    Name = "$AssetName"
                    ThreatNameTag = "$ThreatName"
                    MitigationMode = "$mitigationMode"
                    Resolved = $Resolved
                    Classification = "$Classification"
                    Rank = "$Rank"
                    AgentOS = "$AgentOS"
                    Engines = "$engines"
                    Username = "$username"
                }
        #Write Metric into the Influx Database
        Try {
        Write-Influx -Measure ThreatsbyAgents -Tags $tag -Metrics $InputMetric -TimeStamp $createdDate -Database $Global:Influxdb -Server $Global:InfluxServer -Verbose
        }
        catch
        {
        $ErrorMessage = $_.Exception.Message
        "$Global:ExecuteTime" + " --- " + "$ErrorMessage" + " -- $createdDate -- $SiteName -- $AssetName -- $ThreatName -- $mitigationMode -- $Resolved -- $Classification -- $Rank -- $AgentOS -- $engines -- $username"| Out-file .\SentinelOneError.txt -Append
        }
    }

    $PageCount = $PageCount + $global:SkipValue
    $URLTemp = $URL + "&skip=$PageCount"

    $web1 = Invoke-RestMethod -uri $URLTemp
    $Global:CountWebItem = $web1.data | Measure-Object threatName
    $Global:CountWebItem.Count

    $Global:CurrentRunTimeStamp  + " - " + $URLTemp + " - " + $CountWebItem.Count | Out-file .\SentinelOneTimeLog.txt -Append
    
    } While ($Global:CountWebItem.Count -gt 0)
}
    catch{
    $ErrorMessage = $_.Exception.Message
    "$Global:ExecuteTime" + " --- " + "$ErrorMessage" | Out-file .\SentinelOneError.txt -Append
}
"$Global:CurrentRunTimeStamp" | Out-file .\SentinelOneTimeStamp.txt -Append
"End --- $Global:CurrentRunTimeStamp" | Out-file .\SentinelOneTimelog.txt -Append
}
    

#Get_ThreatByClassification

Get_ActiveThreatByAgent

Start-Sleep -s 10

} While ($t -gt 0)

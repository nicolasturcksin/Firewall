$dossier='C:\Program Files (x86)\Firewall'
$donnee='C:\Program Files (x86)\Firewall\donnee'
$script='C:\Program Files (x86)\Firewall\script'

function dossier(){
   
    if ( -not (Test-Path $dossier))
    {
       mkdir $dossier
    }
    if ( -not (test-path $dossier\whiteliste))
    {
        New-Item "$dossier\whiteliste" -type file
    }
    if ( -not (test-path $donnee))
    {
        "#TYPE System.Management.Automation.PSCustomObject
ip,comp,fw" | Out-File $donnee
    }
    if ( -not (Test-Path $script))
    {
        mkdir $script
    }    

}
#Cette fonction permet de récuperer le log
#qui a declenche le script
function getlog
{
    $log = Get-EventLog Security -InstanceId 4625 -Newest 1
    return $log
}

#Cette fonction permet de recuperer l ip contenu dans le log
function getip($log){
    $log.Message > "$dossier\temp"
    $ip = Select-String -path "$dossier\temp" -pattern "Source Network Address"  
    $ip = $ip -split '\t'
    return $ip[2]
}

#Cette fonction permet de verifier si l ip existe sur la whiteliste ou DB
function check($ip,$chemin){
    $found = Select-string -path $chemin -Pattern $ip
    if ( $found -eq $null)
    {
        return 0
    }
    else
    {
        return 1
    }
}

#Cette fonction cree in script qui va permettre la suppression 
#de la regle firewall dans 7 jours
function script($ip){
     "netsh advfirewall firewall del rule name=$ip`n
     sleep 2`n
     schtasks /delete /tn $ip /f`n
     remove-item `"$script\$ip.ps1`"" | out-file $script\$ip.ps1
}

function newdat(){
    $1=(get-date).AddDays(7)
    $jour=$1.Day
    $mois=$1.Month
    $annee=$1.Year
    $date= echo "$jour/$mois/$annee"
    return $date 
}
#Cette fonction permet de rajouter une regle dans le firewall
#Pour blocker l ip qui a deja fait plus de 3 tentative
function firewall($ip){
    netsh advfirewall firewall add rule name=$ip dir=in action=block remoteip=$ip
    script $ip
    $date = newdat 
    schtasks /create /sc once /st 23:00 /sd $date /tn $ip /TR "powershell -command `"&{$dir\script\$ip.ps1}`""
}

#Cette fonction permet de rajouter l ip dans le fichier de donnee
# si elle existe deja j'incremente son compt de 1
function ajout($ip){
    if ((check $ip "$dossier\whiteliste") -eq 0)
    {
        if ((check $ip $donnee) -eq 0)
        {
            # IP,OCCURENCE,PRESENT FW
            "$ip,1,NO"| Out-File -Append -FilePath $donnee
        }
        else
        {
            $liste = @(Import-Csv $donner)
            $index = select-string -path $donnee -Pattern $ip
            $index = $index -split ':'
            [INT]$index = $index[2]-3
            [INT]$comp = $liste[$index].comp
            $comp++
            if ( $comp -gt 3 )
            {
               firewall $ip 
            }
            $liste[$index].comp = $comp
            $liste | export-csv $donnee    
        }

    }
}

#cette fonction est la fonction principale
function action
{
   dossier
   $log = getlog
   $ip = getip $log
   ajout $ip
   
   
}


action



$query = "SELECT * FROM __instancecreationevent
         WITHIN 3
         WHERE targetinstance ISA 'Win32_NTLogEvent'
         AND targetinstance.logfile='Security'
         AND targetinstance.Eventcode='4625'"

$action = {action}

Register-WmiEvent -query $query -SourceId 'test' -Action $action

$dossier='C:\Program Files (x86)\Firewall'
$donnee='C:\Program Files (x86)\Firewall\donnee'
$script='C:\Program Files (x86)\Firewall\script'
$logfile='C:\Program Files (x86)\Firewall\log'

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
    if ( -not (Test-Path $logfile))
    {
        New-Item $logfile -type file
    }    

}
#Cette fonction permet de récuperer le log
#qui a declenche le script
function getlog
{
    "je recupere le log" | Out-File $logfile -Append
    $log = Get-EventLog Security -InstanceId 4625 -Newest 1
    return $log
}

#Cette fonction permet de recuperer l ip contenu dans le log
function getip($log){
    "je recupere l'ip" | Out-File $logfile -Append
    $log.Message > "$dossier\temp"
    $test=Get-Host
    if ( $test.CurrentUICulture.Name -eq "en-us")
    {
        $ip = Select-String -path "$dossier\temp" -pattern "Source Network Address" 
    }
    else
    {
        $ip = Select-String -path "$dossier\temp" -pattern "Adresse Du Réseau Source"
    } 
    $ip = $ip -split '\t' 
    $ip[2] | Out-File $logfile
    return $ip[2]
}

#Cette fonction permet de verifier si l ip existe sur la whiteliste ou DB
function check($ip,$chemin){
    "je check si l ip existe" | Out-File $logfile -Append
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
     "je cree le script pour suprrimer firewall" | Out-File $logfile -Append
     "netsh advfirewall firewall del rule name=$ip`n
     sleep 2`n
     schtasks /delete /tn $ip /f`n
     remove-item `"$script\$ip.ps1`"" | out-file $script\$ip.ps1
}

#Cette fonction permet de rajouter une regle dans le firewall
#Pour blocker l ip qui a deja fait plus de 3 tentative
function firewall($ip){
    "je rajoute la regle + crontab" | Out-File $logfile -Append
    netsh advfirewall firewall add rule name=$ip dir=in action=block remoteip=$ip
    script $ip
    $date = (Get-Date).AddDays(7).ToString('dd/MM/yyyy') 
    schtasks /create /sc once /st 23:00 /sd $date /tn $ip /TR "powershell -command `"&{$dir\script\$ip.ps1}`""
}

#Cette fonction permet de rajouter l ip dans le fichier de donnee
# si elle existe deja j'incremente son compt de 1
function ajout($ip){
    if ((check $ip "$dossier\whiteliste") -eq 0)
    {
        "l ip n est pas dans whiteliste" | Out-File $logfile -Append
        if ((check $ip $donnee) -eq 0)
        {
            "l ip n est pas dans donnee ajout de celle-ci" | Out-File $logfile -Append
            # IP,OCCURENCE,PRESENT FW
            "$ip,1,NO"| Out-File -Append -FilePath $donnee
        }
        else
        {
            "l ip est deja dans donnee incremente son compteur" | Out-File $logfile -Append
            $liste = @(Import-Csv $donnee)
            $index = select-string -path $donnee -Pattern $ip
            $index = $index -split ':'
            [INT]$index = $index[2]-3
            $liste[$index]
            [INT]$comp = $liste[$index].comp
            $comp++
            if ( $comp -gt 3 )
            {
               "l ip a plus de 3 test je rajoute dans le firewall" | Out-File $logfile -Append
               firewall $ip 
            }
            $liste[$index].comp = $comp
            $liste[$index]
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
   if ( -not ($ip -eq "-"))
   {
        ajout $ip
   }
   
}




$query = "SELECT * FROM __instancecreationevent
          WITHIN 3
          WHERE targetinstance ISA 'Win32_NTLogEvent'
         AND targetinstance.logfile='Security'
          AND targetinstance.Eventcode='4625'"

$action = {action}

Register-WmiEvent -query $query -SourceId 'firewall' -Action $action
Import-Module ActiveDirectory
$MaxPassAge=((Get-ADDefaultDomainPasswordPolicy).MaxPasswordAge)
$DaysInform= "14","7","3","1"
$stage=0
$users=(Get-ADUser -Filter {PasswordNeverExpires -eq $false -and Enabled -eq $true} -Properties PasswordLastSet,Enabled,mail |where {$_.PasswordLastSet -ne $null})
while ($Stage -lt $DaysInform.Count) {
$users | % {

if (($_.PasswordLastSet+$MaxPassAge).addDays(-$DaysInform[$stage]).DayOfYear -eq (get-date).DayOfYear)
{

      $name=($_.name.tostring())
      $adres=($_.mail.tostring())
      $date=($DaysInform[$stage].tostring())
	  
      Send-MailMessage -Encoding ([System.Text.Encoding]::UTF8) -SmtpServer XXXXXXXXXXXXXX -From XXXXXXXXXXXXXX -to "$adres" -Subject "Twoje haslo wygasa za $date dni!" -Attachments "c:\Instrukcja_resetu_hasla.pdf" -BodyAsHtml "<p><strong>Witaj $name !</strong></p>
     <p><strong>Twoje hasło wygaśnie za $date dni!</strong></p>
     <p>Jeżeli Twoje hasło wygaśnie, nie będziesz mógł/mogła zalogować się do usług takich jak VPN</p>
     <p>Żeby zmienić hasło. użyj stacji przesiadkowej lub podpiętego do domeny komputera z systemem Windows zgodnie z instrukcją.</p>
     <p><strong>Pozdrawiamy!</strong></p>
     <p><strong>Oddany dział IT :)</strong></p>" 

}

}
$stage++
}
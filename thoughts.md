Aktuelle Probleme, die in der Bachelorarbeit unbedingt thematisiert werden müssen:



* Weniger Beobachtung: Ohne Hintergrundabrufe sieht der IdP nicht regelmäßig Synchronisationsanfragen, sondern nur Anfragen bei späteren RP-Logins. Er kann diese Logins unter derselben RP-Pairwise-DID weiterhin wiedererkennen. Auch die mögliche zeitliche Zuordnung zur RP-Master-DID bleibt bestehen.
* Andere Aktualitätsgarantie: Du kannst zusagen, dass die Claims bei einem erfolgreichen schnellen Login frisch vom IdP abgerufen wurden. Du kannst nicht zusagen, dass sie während der anschließenden RP-Sitzung aktuell bleiben. Ist der IdP nicht erreichbar, darf der RP für diese Zusage nicht unbemerkt auf alte Claims zurückfallen.
* Refresh-Zähler wird praktikabler: Ohne Polling wird ein Refresh nur benötigt, wenn bei einem Login das Access-Token abgelaufen ist. Acht erlaubte Refreshes sind damit nicht automatisch nach vier Stunden aufgebraucht; ihre Reichweite hängt von der Login-Häufigkeit ab.
* Zugriff ohne Nutzer bleibt technisch möglich: Auch wenn der RP vorgesehen nur nach einem DID-Login abfragt, kann er mit einem gültigen Token grundsätzlich jederzeit beim IdP anfragen. Der IdP prüft mit dem Token die Berechtigung des RP, nicht die tatsächliche Anwesenheit des Nutzers. Das sollte als Grenze der Einwilligung und des Vertrauensmodells in die Arbeit.
* Unverändert: Token-Diebstahl und Replay-Schutz, Widerruf und Ablauf des Grants, die fehlende Garantie gegen Zuordnung des RP, die Nichtübertragbarkeit des RP-Credentials sowie die Unterschiede zwischen RISC Zero und STWO. Auch die fehlende vollständige OIDC-Konformität des derzeitigen Claims-Tokens ändert sich dadurch nicht. 


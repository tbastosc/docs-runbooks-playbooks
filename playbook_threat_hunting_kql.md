<div>

# Threat Hunting Playbook em KQL no Microsoft Defender

<div>

<div>

Playbook, prático para começar threat hunting com Advanced Hunting (KQL) no Microsoft Defender (M365). Inclui queries partilhadas, passos operacionais e boas práticas.

</div>

</div>

## Objetivo, Finalidade e Localizar

·       Objetivo: identificar atividade suspeita cedo, a partir de hipóteses, IoCs e TTPs, usando Advanced Hunting (KQL). Esta ferramenta destaca-se pela flexibilidade na procura e filtro dos padrões IOC’s.

·       Finalidade: Implementar regras de identificação avançada, seja para alarmística ou para resposta a incidentes automatizada

·       Ferramenta: Portal Microsoft Defender → Investigation & Response → Hunting → Advanced hunting.

·       Queries partilhadas: Portal Microsoft Defender → Advanced Hunting → Queries → Shared Queries → nome_empresa

![img_001](assets/img_001.jpg)

## Fluxo Operacional (passo a passo)

1.     Definir hipótese ou gatilho: campanha, TTP, novo IOC.

2.     Escolher fontes: endpoints, identidade, email, cloud apps.

3.     Executar query base (ver exemplos) e validar amostra pequena; depois ampliar janela tempo e filtros.

4.     Enriquecer resultados: juntar (join) com tabelas de identidade/email/alertas.

5.     Priorizar eventos com maior risco.

6.     Registrar IOC encontrados e criar incidente/tarefa de contenção/remediação quando aplicável.

7.     Criar regra personalizada para identificação IOC’s observados, se aplicável.

## Queries (KQL) exemplo partilhadas para reutilização na investigação

1.     Hunting de phishing (Email + Clicks) – reaproveitável para investigações

<div>

<div>

``` jscript
//Investigation, Click Events Associated with Email Delivery events in Inboxes, for targget sender email or domain
```

    let TargetSender = "noreply@example.com";

    EmailEvents

    | where EmailDirection == "Inbound"

    | where SenderFromAddress =~ TargetSender // change variable as needed ex: SenderFromDomain / SenderFromAddress

    | where DeliveryAction == "Delivered"

    | where LatestDeliveryLocation in ("Inbox/folder") // options ("Inbox/folder","Junk Folder","Quarantine","Deleted items folder","On-prem/external)

    | project

        TimeEmail = Timestamp,

        SenderFromAddress,

        RecipientEmailAddress,

        Subject,

        ThreatTypes,

        LatestDeliveryLocation,

        NetworkMessageId

    | join kind=leftouter (

        UrlClickEvents

        | where Workload == "Email"

        | project

            NetworkMessageId,

            TimeClick = Timestamp,

            Url,

            ActionType,

            IsClickedThrough,

            ClickRecipient = AccountUpn

    ) on NetworkMessageId

    | extend Clicked = iff(isnotempty(TimeClick), "Sim", "Não")

    | order by TimeEmail desc

</div>

</div>

2.     Hunt URL’s potencialmente maliciosos remetem para executáveis – reaproveitável para investigações ou regras

<div>

<div>

``` jscript
//OBJECTIVE look for potencial malicious URL that point to executable files
```

    //ATTENTION - BE AWARE OFF EXCEPTIONS CREATED BELLOW

    let ClickedUrls =

        UrlClickEvents

        | project

            NetworkMessageId,

            Url,

            ClickedTime = Timestamp;

    EmailUrlInfo

    | where tolower(Url) has ""                         //add exact expressions to look for

    //| where not(tolower(Url) has_any ("dropbox.com","lexmark.com")) //EXCEPTIONS to not look for!!!!!! reduce double alerts

    | extend FileExt = extract(@"\.([a-zA-Z0-9]+)(\?|$)", 1, Url)

    | extend FileName = extract(@"/([^/?#]+)(?:\?|#|$)", 1, Url)

    | where tolower(FileExt) in ("exe","msi","hta","ps1","vb","vbe","lnk","cmd","ws","wsf","bat")

    | where not(Url matches regex @"(?i)\.(exe|msi)\.(png|jpg|txt|pdf)")

    | join kind=inner EmailEvents on NetworkMessageId

    //

    | where DeliveryAction == "Delivered" 

    //| where DeliveryLocation == "Inbox/folder"

    | where LatestDeliveryLocation == "Inbox/folder"    //"Deleted items", "Inbox/folder", "Forwarded", "On-premises/external"

    //

    // joins clicks information

    | join kind=leftouter ClickedUrls on NetworkMessageId, Url

    | extend Clicks = iff(isnotempty(ClickedTime), "YES", "NO")

    //

    //exclutions for intern domains

    | where RecipientEmailAddress !in ("soc@dominio.pt")

    | where

        SenderFromDomain !in ("dominio.pt", "parceiro.dominio.pt")

        or SenderFromAddress in (

        )

    //whitelisting reviewed 18/05/2026, should remove after 15/06/2026 "commum-email-example@domain.com"

    | where SenderFromAddress !in ("commum-email-example@domain.com")

    // severity 

    | extend Severity = case(

        Clicks == "YES", "High",

        LatestDeliveryLocation == "Inbox/folder", "Medium",

        "LOW"

    )

    | project

        Timestamp,

        SenderFromAddress,

        RecipientEmailAddress,

        Subject,

        Url,

        FileName,

        FileExt,

        Clicks, 

        DeliveryAction,

        DeliveryLocation,

        LatestDeliveryLocation,

        Severity,

        ThreatTypes,

        InternetMessageId,

        RecipientObjectId,

        NetworkMessageId,

        ReportId

    |sort by Timestamp

</div>

</div>

3.     Hunting de Phishing por anexos .pdf

<div>

<div>

``` jscript
// This querie looks for a specific PDF attachment by expression (example) file name
```

    EmailAttachmentInfo

    | where tolower(FileName) matches regex tolower(@"*(example).*\.pdf") //change regex as needed

    | join kind=inner EmailEvents on NetworkMessageId

    | where DeliveryAction == "Delivered"

    // comment/uncomment, to validade every case for risk analysis!

    //| where DeliveryLocation == "Inbox/folder"

    | where LatestDeliveryLocation == "Inbox/folder"

    | where RecipientEmailAddress != "soc@dominio.pt"

    | project

        Timestamp,

        SenderFromAddress,

        RecipientEmailAddress,

        Subject,

        FileName,

        FileSize,

        LatestDeliveryLocation,

        DeliveryLocation,

        DeliveryAction,

        ThreatTypes,

        SHA256

    | order by Timestamp desc

</div>

</div>

4.     Hunting de Phishing por anexos .zip

<div>

<div>

``` jscript
//This querie looks for expecific reg.expression in email ZIP files attachments 
```

    EmailAttachmentInfo

    | where FileType == "zip"

    | where tolower(FileName) matches regex tolower(@"(comprovativo-janeiro|comprovativo-fevereiro|comprovativo-março|comprovativo-abril|comprovativo-maio|comprovativo-junho|comprovativo-julho|comprovativo-agosto|comprovativo-setembro|comprovativo-outubro|comprovativo-novembro|comprovativo-dezembro).*\.zip") //change values as needed

    | join kind=inner EmailEvents on NetworkMessageId

    | where DeliveryAction == "Delivered"

    //comment/uncomment, to validate everycase for risk analisys!

    //| where DeliveryLocation == "Inbox/folder"

    | where LatestDeliveryLocation == "Inbox/folder"

    | where RecipientEmailAddress != "soc@dominio.pt"

    | project

        Timestamp,

        SenderFromAddress,

        RecipientEmailAddress,

        Subject,

        FileName,

        FileSize,

        LatestDeliveryLocation,

        DeliveryLocation,

        DeliveryAction,

        ThreatTypes,

        InternetMessageId,

        RecipientObjectId,

        NetworkMessageId,

        SHA256

    | order by Timestamp desc

</div>

</div>

5.     Investigação de anomalias, listagem e enumeração

<div>

<div>

``` jscript
//Querie to list emails delivered from SenderFromDomain, by Recipient and Subject
```

    EmailEvents

    | where Timestamp >= ago(1d)

    | where SenderFromDomain == "example.com"

    | where DeliveryAction == "Delivered"

    | project

        Timestamp,

        RecipientEmailAddress,

        Subject

    | sort by Timestamp desc

    | summarize

        EmailsPorRecipiente = count(),

        EmailsDetalhe = make_list(

            pack(

                "Timestamp", Timestamp,

                "Subject", Subject

            )

        )

        by RecipientEmailAddress

    | sort by EmailsPorRecipiente desc

    | summarize

        TotalEmails = sum(EmailsPorRecipiente),

        TotalRecipientes = dcount(RecipientEmailAddress),

        Detalhe = make_list(

            pack(

                "Recipient", RecipientEmailAddress,

                "Emails", EmailsPorRecipiente,

                "DetalheEmails", EmailsDetalhe

            )

        )

</div>

</div>

6.     Investigação possível phishing por relação domínios raros vs recepção em múltiplas caixas recipientes

<div>

<div>

``` jscript
let RareDomainThreshold = 20;
```

    let TotalSenderThreshold = 2;

    let RareDomains = EmailEvents

    | summarize TotalDomainMails = count() by SenderFromDomain

    | where TotalDomainMails <= RareDomainThreshold

    | project SenderFromDomain;

    EmailEvents

    | where EmailDirection == "Inbound"

    | where SenderFromDomain in (RareDomains)

    | where LatestDeliveryAction == "Delivered"

    | where DeliveryLocation == "Inbox/folder"

    | where isnotempty(EmailClusterId)

    | join kind=inner EmailUrlInfo on NetworkMessageId

    | summarize

        Subjects = make_set(Subject),

        Senders = make_set(SenderFromAddress),

        Recipients = make_set(RecipientEmailAddress),

        TotalRecipients = dcount(RecipientEmailAddress)

      by EmailClusterId

    | extend TotalSenders = array_length(Senders)

    | where TotalSenders >= TotalSenderThreshold

</div>

</div>

7.     Casos similares por IMID. Util para procurar similares e clicks.

<div>

<div>

``` jscript
8.  let EmailsDoSender =
```

    9.  EmailEvents

    10.//| where Timestamp > ago(30d)

    11.| where InternetMessageId == "<idddddddddddddddddddddd.eurprd05.prod.outlook.com>"

    12.//| where InternetMessageId has "prod.outlook.com"

    13.| project TimeEmail = Timestamp,

    14.          RecipientEmailAddress,

    15.          SenderFromAddress,

    16.          SenderFromDomain,

    17.          Subject,

    18.          ThreatTypes,

    19.          DeliveryLocation,

    20.          InternetMessageId,

    21.          NetworkMessageId;

    22.EmailsDoSender

    23.| join kind=leftouter ( 

    24.    UrlClickEvents

    25.    | where Workload == "Email"

    26.    | where ActionType == "ClickAllowed" or IsClickedThrough != "0"

    27.    | project NetworkMessageId,

    28.              TimeClick = Timestamp,

    29.              Url,

    30.              UrlChain,

    31.              ActionType,

    32.              IsClickedThrough

    33.) on NetworkMessageId

</div>

</div>

34.  Hunting - Track casos de spam/phishing multi-stage por fingerprinting. (exemplo)

<div>

<div>

``` jscript
//target campaign may spam/phis
```

    //query maintained tabastos

    EmailEvents

    | where Subject contains "Collaboration - Ref ID:"

    | where LatestDeliveryLocation == "Inbox/folder"

    | where RecipientEmailAddress !in ("soc@dominio.pt")

    | project Timestamp, RecipientEmailAddress, Subject, 

            SenderFromAddress, SenderFromDomain, 

            ThreatTypes, LatestDeliveryLocation, NetworkMessageId

    | order by Timestamp desc

</div>

</div>

## Boas práticas de Hunting (KQL + Operação)

·       Iterar rápido: começar com filtros específicos (tempo/host/conta) e alargar gradualmente.

·       Documentar hipóteses, queries, resultados e decisões; reutilizar snippets aprovados.

·       Usar summarize e join com parcimónia para evitar custos/tempo altos; projetar apenas colunas úteis.

·       Enriquecer com telemetria de identidade e email para contexto de pessoa e campanha.

·       Criar bookmarks e exportar resultados para investigação/automação posterior.

·       Regras requerem optimização adequada para reduzir falsos positivos.

## Criar Regras - considerações

·       Devem de estar bem optimizadas antes de realizar ações de modo a evitar falsos positivos.

·       Devem ser aprovadas e coordenadas com SOC IR de modo a agregar alertas no SIEM/SOAR

·       Documentação relevante: [Create custom detection rules in Microsoft Defender XDR - Microsoft Defender XDR \| Microsoft Learn](https://learn.microsoft.com/en-us/defender-xdr/custom-detection-rules)

## Erros comuns e como evitar

·       Queries sem limite temporal → usar ago() adequado e só depois ampliar ou definir janela tempo personalizado na barra superior.

·       Selecionar colunas demais → usar project cedo para reduzir custo/latência.

·       Join pesado desnecessário → validar hipóteses numa tabela antes de correlacionar.

## Referências

·       [Create custom detection rules in Microsoft Defender XDR - Microsoft Defender XDR \| Microsoft Learn](https://learn.microsoft.com/en-us/defender-xdr/custom-detection-rules)

·       [Overview - Advanced hunting - Microsoft Defender XDR \| Microsoft Learn](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-overview)

·       [Custom detection rules in Microsoft Defender - short guide \| Kacper SecOps-Blog](https://kacyper44.github.io/defender/2024/12/01/Custom-detection-rules.html)

## Contactos e responsabilidades

·       Owner do Playbook: *\[tabastos@dominio.pt\]*

·       Revisão de queries e tuning: *\[*<TABASTOS@dominio.pt>*\]\[*

</div>

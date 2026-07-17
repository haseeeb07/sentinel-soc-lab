# 01 - Azure Setup

This is the foundation phase of the lab: standing up the Azure resources that everything else runs on. The goal here is a working Microsoft Sentinel workspace ready to ingest data and fire detections.

## What I built

| Resource | Name | Region | Purpose |
|----------|------|--------|---------|
| Resource group | `rg-soc-lab` | Australia East | Container for all lab resources, so everything can be torn down together |
| Log Analytics workspace | `law-soc-lab` | Australia East | The data store where logs are collected and queried with KQL |
| Microsoft Sentinel | (on `law-soc-lab`) | Australia East | SIEM layer sitting on top of the workspace for detection, investigation, and response |

## Steps

1. Signed up for an Azure free account ($200 credit, 30 days).
2. Created the resource group `rg-soc-lab` in Australia East. A resource group is just a container, so it costs nothing on its own and keeps every lab resource in one place for easy cleanup.
3. Created a Log Analytics workspace `law-soc-lab` in the same region. This is the underlying store that holds all ingested log data and is what KQL queries run against.
4. Enabled Microsoft Sentinel on that workspace, which started the 31-day Sentinel free trial (up to 10GB/day ingestion included).

## Notes and things I learned

- **Region consistency matters.** Keeping the resource group, workspace, and Sentinel all in Australia East avoids cross-region data transfer and keeps latency down.
- **Sentinel is moving to the Defender portal.** During setup, Azure showed a banner that the standalone Sentinel experience in the Azure portal is scheduled for retirement, with the unified experience moving to the Microsoft Defender portal (security.microsoft.com). Worth doing some of the lab work in the Defender portal view to stay current with where the tooling is heading.
- **Cost control.** The workspace is billed pay-as-you-go per GB, but the free trial covers far more ingestion than this lab needs. Set a budget alert as a habit; the real spend risk comes later when VMs get added.

## Cost management

- Budget alert set at $20/month with a notification at 50%.
- No VMs deployed yet, so current spend is effectively zero (Sentinel trial covers ingestion).
- Plan: delete the resource group at the end of the lab to stop all charges.

## Next step

Deploy the Microsoft Sentinel Training Lab from the Content Hub to load pre-recorded attack data, detection rules, and incidents — then work the first incident and document it in `reports/incident-001.md`.

# Validation methodology

Every rule here is tested against real attack telemetry, not just written and
hoped over. No synthetic or hand-edited events are used as evidence.

## Windows (Sigma)
- **Corpus:** [EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES)
  — real Windows event logs captured from live attack techniques, organized by ATT&CK ID.
- **Runner:** [Chainsaw](https://github.com/WithSecureLabs/chainsaw) executes the
  Sigma rule directly against the `.evtx`.
- **Reproduce:**
  ```
  chainsaw hunt <sample.evtx> --sigma <rule.yml> --mapping mappings/sigma-event-logs-all.yml
  ```
  The matched event in each rule's `## Validation` section is the real Chainsaw output.

## Cloud (KQL)
- **Corpus:** [OTRF Security-Datasets](https://github.com/OTRF/Security-Datasets)
  — pre-recorded AWS CloudTrail and Azure/Entra telemetry mapped to ATT&CK.
- **Runner:** an Azure Data Explorer free cluster (https://dataexplorer.azure.com/freecluster)
  with the dataset ingested; the `detection.kql` is run against it.
- Where a public dataset does not reproduce a specific pattern, the writeup says
  so and validates the field logic against the documented log schema.

## Status today
- Windows rules (T1053.005, T1003.001, T1059.001, T1543.003): **validated** — real
  Chainsaw hits on EVTX-ATTACK-SAMPLES, evidence in each writeup.
- Cloud rules (T1098.001, T1621): **draft** — KQL authored against the documented
  Sentinel schema; Azure Data Explorer validation in progress.

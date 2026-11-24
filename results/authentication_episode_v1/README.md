# Authentication episode research

The follow-up feedback supports keeping authentication and single-request Web evidence as separate inputs. The first implementation extracts both from the saved phone recordings and evaluates authentication by episode. Code40 remains the active release.

## Dataset and evidence

The dataset contains **520 causal prefixes from 30 service episodes**. A prefix is what the detector could see at the time a qualifying connection summary arrived. The 20 HTTP episodes retain the original 14/3/3 training, validation and test session allocation. The other ten episodes are from the four normal protocol cases and the two FTP/SSH guessing cases. They contain four normal episodes and one guessing episode per protocol. SSH and FTP are too sparsely represented for supervised episode fitting or evaluation of a cross-protocol classifier.

Inbound TCP connections contribute to both peer-and-service and service-wide histories. Each scope measures repetition, peer diversity, arrival spacing, duration, directional bytes and resets over 5, 30, 120 and 300 seconds. Service history starts a new episode after a gap greater than 300 seconds. Repeated segments with a previously observed tuple and protocol are conservatively counted once per recording. A future live version would need explicit connection generations and bounded state. HTTP 401/403 counts and response-observation counts describe the limited cleartext response evidence. SSH and FTP input vectors carry zero HTTP observations. The extractor never infers encrypted login results.

Protocol cues, current flow statistics and prior observations are the only feature inputs. Verified controller/server labels are joined after extraction by matching exact flow identity. An episode with any unlabeled authentication prefix is ineligible for scored evaluation. Mixed HTTP sessions contain both ordinary logins and guessing. Training targets for a prefix turn positive only once the episode has a verified positive prefix. The classifier receives feature fields only. Source, port, session, baseline flag, verified subtype, outcome and route are excluded as model inputs.

For each positive episode, record whether the first candidate warning occurred before the first verified attack prefix, whether any warning followed that prefix, and warning delay from the earliest captured positive connection start. The first-warning metric counts only the episodes whose first warning is at or after the first verified prefix. This is stricter than counting any later warning after a premature one. A connection in the retained earlier context was observed, not detected at that earlier time.

## Retrospective HTTP results

| Candidate | Test episodes with a warning at or after the positive prefix | Normal test episodes flagged | First warning on positive episode |
|---|---:|---:|---|
| Code40 rescored on the saved inputs | 2/2 | 0/1 | One warning preceded the first verified positive prefix, after the first guessing connection had already started. The other took 2.43 s. |
| Four connections in 30 seconds | 2/2 | 1/1 | 6.46 s and 4.27 s |
| Peer 30-second logistic, selected on validation | 2/2 | 1/1 | 37.07 s and 2.43 s |
| Peer multi-window logistic | 2/2 | 0/1 | 31.41 s and 2.43 s |
| Peer plus service multi-window logistic | 2/2 | 0/1 | 33.27 s and 2.43 s |

The four-connection rule flagged all six normal-only HTTP sessions across the three partitions. This is direct evidence against transferring the SSH/FTP heuristic to HTTP. All three models tied on the validation episode metrics and first-warning times, so the implementation chose the smaller model. Its false test alert rules out promotion. The longer-window test results are descriptive and have substantial latency. One normal test episode cannot establish normal-use specificity. The current HTTP baseline was rescored from the frozen Code40 gate. Original capture flags in the dataset summary belong to the earlier v2 gate and are reported separately.

Training used only HTTP prefixes, with weights proportional to the inverse number of prefixes per episode, then class balancing. It preserves session boundaries and avoids duplicate row replay. The selection rule required zero normal and premature warnings on validation, then maximized detected episodes and minimized mean warning delay. This was a retrospective experiment on an already examined split, so validation-selected weights and reviewed test results do not establish readiness for fresh traffic.

In the saved FTP/SSH cases the four-connection rule identified both guessing episodes without flagging any of eight normal protocol episodes. Code40 also flagged both guessing episodes and flagged six of eight normal episodes. The rule moved SSH's first warning from 0.41 to 1.70 seconds and left FTP's first warning at 3.08 seconds. These episode-specific counts exclude normal HTTP probes and therefore answer a different question from the prior 13/36 normal-connection comparison.

## Decisions for the next study

- Keep the multiscale peer and service features to test on fresh recordings. Evaluate first-warning delay and false normal episodes alongside detection. Include ordinary reconnect bursts, concurrent legitimate logins, and independent recorded slow and multi-source cases. Assign whole recording sessions and devices to evaluation partitions before fitting or inspecting candidate predictions. The current datasets contain one phone and too few independent normal and attack sessions to select a release policy.
- Keep SQL/XSS cues available independently of the authentication route. In the test split the semantic cue appeared on all 24 confirmed SQL/XSS examples and on three of twelve ordinary search/code requests. It is a routing feature for future evaluation. A cue alone would generate false alarms. The synthetic check confirms that one observation can enter both routes.
- Describe DoS/DDoS using fixed service-time windows rather than applying a service label to every connection. Before fitting a pressure specialist, require verified healthy multi-client recordings from the same service under comparable normal load. Use service response evidence to label episodes separately from network inputs. The saved single-source normal controls cannot distinguish distributed activity from legitimate concurrent clients.
- Keep Bot timing as a research feature until matched normal periodic traffic is available. Keep the Code40 path as the baseline for all comparisons. Defer complex temporal models and changes to gate routing until simpler episode models hold up on independent recordings.

## Reproduction

Use the private captures on the work PC. The dataset and fitted research weights are written under `runs/authentication_episode_v1`. No packet generation is involved.

```powershell
python validation/authentication_episodes.py
wsl.exe -d Ubuntu --cd <PROJECT_ROOT> --exec <PROJECT_ROOT>/.venvs/edge-export/bin/python validation/compare_authentication_episodes.py
```

The checks exercised causal prefix order, duplicate suppression, scope separation, expiry, simultaneous semantic/authentication cues and the frozen split counts. [Dataset and routing audit](dataset_summary.json) · [HTTP episode comparisons](http_episode_comparison.json)

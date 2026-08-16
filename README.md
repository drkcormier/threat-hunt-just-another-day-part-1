<img width="824" height="306" alt="image" src="https://github.com/user-attachments/assets/b7e890c1-aae1-4664-b21e-b661d59c298f" />

## Part 1 - Threat Hunt Brief

### **[ORG] // a routine posture review that turns out to be anything but**
<img width="820" height="178" alt="image" src="https://github.com/user-attachments/assets/77e3e109-9ac4-422c-b390-3ccb2d5095bd" />

---
### **REVIEW BRIEF**

**REVIEW ASSIGNMENT // [ORG SOC]**

**From:** Hunt Lead // [ORG SOC]
**To:** DCormier // on shift
**Re:** ORG // billing account posture review
Your shift starts with a routine one. Nimbus Health, a small outpatient clinic we support, asked for a posture review after a billing account showed some odd activity. The paperwork calls it a stale-access housekeeping check. Read it as an investigation anyway, and let the telemetry decide what it actually is.

The account in question belongs to a billing analyst. On paper, submissions work, nothing more. In the logs, that account is doing things a billing analyst has no business doing, and it's being used in a way that should make you look twice at where it's being used from.

What we need you to work out:

   · Whether this is really a curious employee, or something else
   · What the account did that falls outside its role
   · What sensitive material it reached, and where that material ended up
   · Whether it stayed on one machine, or moved
   · The honest root cause, once you've seen the evidence

One thing to hold from the start. The clinic wants this written up as an insider who forgot to hand back some access. Don't accept that on trust. Some of the strongest evidence here is about where the account is being driven from, and some of it is about what you don't find. Follow the logs, not the paperwork.

Work it end to end. Reconstruct what the account did, in order. Reason where the evidence is thin. There's noise in here that looks like activity and isn't, learn to cut it. Then give the honest read.

Get hunting.
**// Hunt Lead**
[ORG SOC] · [ORG] series, part one

---
### Investigation Report
[Investigation Report](https://github.com/drkcormier/threat-hunter-just-another-day-part-1/blob/main/just-another-day-p1-investigation-report.md)

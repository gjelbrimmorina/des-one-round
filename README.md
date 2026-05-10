# des-one-round.git
Implementation of a single DES round with manual SubKey input | Data Security - Project III
# Project III — Data Security

## Group 7: One-Round DES Implementation

> **Topic:** Write an application that implements only one Round of the DES Algorithm. The SubKey must NOT be generated automatically — it must be provided to the application manually.
>
> **Reference:** Internet Security – Cryptographic Principles, Algorithms and Protocols (Man Young Rhee, John Wiley & Sons, 2003), **Figures 3.1 and 3.2, page 59**.

---

## Table of Contents

- [Project Description](#project-description)
- [How a DES Round Works](#how-a-des-round-works)
- [Project Structure](#project-structure)
- [How to Run](#how-to-run)
- [Example Execution](#example-execution)
- [Testing](#testing)
- [Tables Used](#tables-used)

---

## Project Description

This application implements **only one Round** of the standard DES algorithm (Data Encryption Standard, FIPS 46-3). Unlike the full DES algorithm which has 16 rounds and generates 16 subkeys from an initial 64-bit key, this application:

- Implements **only 1 round**.
- **Does NOT generate** the SubKey automatically (no Key Schedule).
- Allows the user to provide the 48-bit SubKey **manually** as input.
- Allows choosing between two modes:
  - **With IP and IP⁻¹** (Initial and Final Permutation, per Figure 3.1)
  - **Round only** (without IP/IP⁻¹ permutations, per Figure 3.2)

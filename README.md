# FirmRES
A new solution that automatically reconstructs device-cloud messages.

# Core Concepts and Preliminary Implementation of FirmRES

This document outlines the core concepts and preliminary implementation of FirmRES (due to additional considerations, we are unable to open-source the final version), which mainly includes the conceptual implementation of cloud program identification and message reconstruction. We hope that by sharing our basic framework and core algorithms, we can provide some ideas and inspiration.

## Runtime Requirements:
- Ghidra 11.1.2 or higher
- intellij-ghidra v0.4.2
- jdk17

## Usage Instructions:
- For cloud program identification, run `CloudIdentifyMain.java`.
- For message reconstruction, run `MessageMain.java`.

## Code Explanation:
1. `Myghidra.java`: Used to record some common processing methods and data structures.
2. `Taint_Trace.java`: Used for backward taint analysis.
3. `libFunction.json`: Records the pollution transmission relationships of some library functions. It includes pollution transmission relationships, where the pollution source sequence corresponding to the parameter will contaminate the target sequence number corresponding to the parameter. `-1` indicates output, `0` is the function name.
   - "name": Function name
   - "group1": The target parameter sequence number for pollution transmission.
   - "group2": The source sequence number of the pollution.

4. `testFirmware`: Available test cases.

## Results Explanation:
1. MFTree slices are located in `/out/Slices`.
2. Message Tree is in `/out/ReconstMsg`.
3. Taint analysis runtime logs are in `/out/running.log`.
4. Message reconstruction logs are in `/out/Reconstruction_Results.log`.

# Details of FirmRES
Device-cloud interfaces are a critical component of IoT given their centrality of the cloud-side control over the connected devices, which has attracted an increasing number of attacks exploiting their access control. Regrettably, there is a lack of techniques to facilitate the examination of such a critical interface, primarily hindered by the challenges of dynamic firmware analysis to reconstruct device-cloud messages and generate testing cues.

This paper presents FirmRES, a principled static approach that automatically reconstructs device-cloud messages by modeling message construction semantics in IoT firmware. At the center of \tool is a message field tree which is formed of the backward data flows from message delivery callsites to the potential sources of message fields. By walking through, transforming, and contextual learning from this tree, device-cloud messages are automatically reconstructed and a set of semantics during ``message construction'' such as the message format, the field semantics, and the order of the fields are inferred. 

We will continue to update our data, models, and conceptual code after the paper is FINALLY ACCEPTED!

# Paper of FirmRES
Yuting Xiao, Jiongyi Chen*, Yupeng Hu*, Jing Huang. FIRMRES: Exposing Broken Device-Cloud Access Control in IoT Through Static Firmware Analysis. The 54th Annual IEEE/IFIP International Conference on Dependable Systems and Networks (DSN 2024), Brisbane, Australia, June 24-27, pp.495-506.

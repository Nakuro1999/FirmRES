# FirmRES
A new solution that automatically reconstructs device-cloud messages.
# Details of FirmRES
Device-cloud interfaces are a critical component of IoT given their centrality of the cloud-side control over the connected devices, which has attracted an increasing number of attacks exploiting their access control. Regrettably, there is a lack of techniques to facilitate the examination of such a critical interface, primarily hindered by the challenges of dynamic firmware analysis to reconstruct device-cloud messages and generate testing cues.

This paper presents FirmRES, a principled static approach that automatically reconstructs device-cloud messages by modeling message construction semantics in IoT firmware. At the center of \tool is a message field tree which is formed of the backward data flows from message delivery callsites to the potential sources of message fields. By walking through, transforming, and contextual learning from this tree, device-cloud messages are automatically reconstructed and a set of semantics during ``message construction'' such as the message format, the field semantics, and the order of the fields are inferred. 

We will continue to update our data, models, and conceptual code after the paper is ONLINE!

# Paper of FirmRES
Yuting Xiao, Jiongyi Chen*, Yupeng Hu*, Jing Huang. FIRMRES: Exposing Broken Device-Cloud Access Control in IoT Through Static Firmware Analysis. The 54th Annual IEEE/IFIP International Conference on Dependable Systems and Networks (DSN 2024) , forthcoming.

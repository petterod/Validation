# Validation
Validation process of anonymization techniques used on different network traffic logs

This repository contains programs for formatting NetFlow logs, web server logs and syslogs, grouping packets into objects,
adding inter- and intra-records, performing feature selection, and mapping anonymized objects to unanonymized objects. 

## AddingRecords
AddingRecords adds inter- and intra-records to IPv4/IPv6/NetFlow/webserver/syslog. It also groups packets into objects since ObjectGrouping
is run from within AddingRecords. It requires both a text file with the original log and a text file with the anonymized log, as input.
These text files need to follow the format from one of the Formatting programs, depending on which log is selected. 
Output files need to be specified, and is the original and anonymized logs, with inter- and intra-records added to them.
Exported as a runnable JAR file, it can be used as such (where * is IPv4/IPv6/NetFlow/Webserver/Syslog):

java -jar AddingRecords*.jar original-input-text-file anonymized-input-text-file original-output-text-file anonymized-output-text-file

## Entropy 
Entropy contains the methods entropy, mutual information, normalized mutual information and L1 similarity. These methods are used
FeatureSelection, ObjectAnonymity and Validation to be able to validate different anonymization techniques.

## FeatureSelection
FeatureSelection groups fields that are dependent on each other, together. The logtype (IPv4/IPv6/NetFlow/webserver/syslog) needs to
be specified. It requires both a text file with the original log and a text file with the anonymized log, as input. Both of these
text files need to contain inter- and intra-records. In other words, they should be outputs from one of the AddingRecords-programs.
Output files need to be specified, and is the original and anonymized logs, with feature selection performed on them.
Exported as a runnable JAR file, it can be used as such:

java -jar FeatureSelection.jar logtype original-input-text-file anonymized-input-text-file original-output-text-file anonymized-output-text-file

## FormattingNetFlow
FormattingNetFlow formats an input NetFlow log to this format: 

Start Time - First Seen | End Time - Last Seen | Duration | Protocol | Source IP Address | Destination IP Address | Source Port |
Destination Port | Source AS | Destination AS | Input Interface Num | Output Interface Num | Packets | Bytes | Flows | Flags | 
ToS | Bytes per Second | Packets per Second | Bytes per Packet

FormattingNetFlow requires an input text file and an output text file. It is heavily dependent upon the field indexes from the input
text file. Exported as a runnable JAR file, it can be used as such:

java -jar FormattingNetFlow.jar original-input-text-file formatted-output-text-file

## FormattingSyslog
FormattingSyslog formats an input syslog to this format: 
Timestamp | Hostname | App-name | Message

FormattingSyslog requires an input text file and an output text file. It is heavily dependent upon the field indexes from the input
text file. Exported as a runnable JAR file, it can be used as such:

java -jar FormattingSyslog.jar original-input-text-file formatted-output-text-file

## FormattingWebserver
FormattingWebserver formats an input web server log to this format: 
IP Address | Identification Protocol | Userid | Timestamp | Request Method | Request | HTTP-version | HTTP-status code | Object Size

FormattingWebserver requires an input text file and an output text file. It is heavily dependent upon the field indexes from the input
text file. Exported as a runnable JAR file, it can be used as such:

java -jar FormattingWebserver.jar original-input-text-file formatted-output-text-file

## ListComparators
ListComparators are used in ObjectGrouping to sort object numbers.

## ObjectAnonymity
ObjectAnonymity performs multiple calculations, like the entropy calculation for every anonymized object and feature, and the probabilities
of unanonymized objects. ObjectAnonymity is used in Validation.

## ObjectGrouping
ObjectGrouping is used in AddingRecords to group packets into objects and assign an object number to each packet.

## Validation
Validation performs the mapping between all anonymized and unanonymized objects. It runs ObjectAnonymity. It requires the original log
and the anonymized log in two text files, as input. Both text files should be the outputted text files from FeatureSelection.
The output is a csv file containing the results from the mapping process. This includes average entropy for anonymized objects, 
maximum entropy for anonymized objects, and mismappings between anonymized and unanonymized objects, from every mapping.
Exported as a runnable JAR file, Validation can be run as such:

java -jar Validation.jar original-input-text-file anonymized-input-text-file results-output-csv-file

/*
# author: Shaun McCullough
# Based on some sample queries I found in the Splunk forums
# 
# Email: cybergoof@gmail.com
# Last Update: 8/26/2017
# SQL Query to extract the McAfee EVO Events.  Only higher threat events
#   Does not extract Whitelisting events or data loss prevention events to reduce noise

# README
# This query is designed to be used by the Logstash input JDBC plugin.  It will 
#   pull all new events up the last week.
*/

SELECT
        [EPOEvents].[ReceivedUTC] as [timestamp],
        [EPOEvents].[AutoID] as [id],
        [EPOEvents].[ThreatName] as [threat_name],
        [EPOEvents].[ThreatType] as [threat_type],
        [EPOEvents].[ThreatEventID] as [threat_event_id],
        [EPOEvents].[ThreatCategory] as [threat_category],
        [EPOEvents].[ThreatSeverity]  as [threat_severity],
        [EPOEventFilterDesc].[Name] as [event_description],
        [EPOEvents].[DetectedUTC] as [detected_timestamp],
        [EPOEvents].[TargetFileName] as [file_name],
        [EPOEvents].[AnalyzerDetectionMethod] as [detection_method],
        [EPOEvents].[ThreatActionTaken] as [action_taken],
        CAST([EPOEvents].[ThreatHandled] as int) as [threat_handled],
        [EPOEvents].[TargetUserName] as [logon_user],
        [EPOComputerProperties].[UserName] as [user],
        [EPOComputerProperties].[DomainName] as [destination_domain],
        [EPOEvents].[TargetHostName] as [destination_host_name],
        [EPOComputerProperties].[IPHostName] as [fqdn],
        [destination_ip] = (convert(varchar(3),

        /* Converts a stored integer into a readable IPv4 address */
        convert(tinyint,substring(convert(varbinary(4),
        convert(bigint,([EPOComputerProperties].[IPV4x] + 2147483648))),1,1)))+'.'+
        convert(varchar(3),convert(tinyint,substring(convert(varbinary(4),
        convert(bigint,([EPOComputerProperties].[IPV4x] + 2147483648))),2,1)))+'.'+
        convert(varchar(3),convert(tinyint,substring(convert(varbinary(4),
        convert(bigint,([EPOComputerProperties].[IPV4x] + 2147483648))),3,1)))+'.'+
        convert(varchar(3),convert(tinyint,substring(convert(varbinary(4),
        convert(bigint,([EPOComputerProperties].[IPV4x] + 2147483648))),4,1))) ),
        [EPOComputerProperties].[SubnetMask] as [destination_net_mask],
        [EPOComputerProperties].[NetAddress] as [destination_mac],
        [EPOComputerProperties].[OSType] as [os],
        [EPOComputerProperties].[OSServicePackVer] as [service_pack],
        [EPOComputerProperties].[OSVersion] as [os_version],
        [EPOComputerProperties].[OSBuildNum] as [os_build],
        [EPOComputerProperties].[TimeZone] as [timezone],
        [EPOEvents].[SourceHostName] as [source_host_name],
        /* Converts a stored integer into a readable IPv4 address */
        [source_ip] =
        ( convert(varchar(3),convert(tinyint,substring(convert(varbinary(4),
        convert(bigint,([EPOEvents].[SourceIPV4] + 2147483648))),1,1)))+'.'+
        convert(varchar(3),convert(tinyint,substring(convert(varbinary(4),
        convert(bigint,([EPOEvents].[SourceIPV4] + 2147483648))),2,1)))+'.'+
        convert(varchar(3),convert(tinyint,substring(convert(varbinary(4),
        convert(bigint,([EPOEvents].[SourceIPV4] + 2147483648))),3,1)))+'.'+
        convert(varchar(3),convert(tinyint,substring(convert(varbinary(4),
        convert(bigint,([EPOEvents].[SourceIPV4] + 2147483648))),4,1))) ),
        [EPOEvents].[SourceMAC] as [source_mac],
        [EPOEvents].[SourceProcessName] as [process_name],
        [EPOEvents].[SourceURL] as [source_url],
        [EPOEvents].[SourceUserName] as [source_logon_user],
        [EPOComputerProperties].[IsPortable] as [is_laptop],
        [EPOEvents].[AnalyzerName] as [analyzer_name],
        [EPOEvents].[Analyzer] as [analyzer],
        [EPOEvents].[AnalyzerVersion] as [analyzer_version],
        [EPOEvents].[AnalyzerEngineVersion] as [analyzer_engine_version],
        [EPOProdPropsView_VIRUSCAN].[datver] as [vse_dat_version],
        [EPOProdPropsView_VIRUSCAN].[enginever64] as [vse_engine64_version],
        [EPOProdPropsView_VIRUSCAN].[enginever] as [vse_engine_version],
        [EPOProdPropsView_VIRUSCAN].[hotfix] as [vse_hotfix],
        [EPOProdPropsView_VIRUSCAN].[productversion] as [vse_product_version],
        [EPOProdPropsView_VIRUSCAN].[servicepack] as [vse_sp]
FROM [EPOEvents]
        left join [EPOLeafNode] on
        [EPOEvents].[AgentGUID] = [EPOLeafNode].[AgentGUID]
        left join [EPOProdPropsView_VIRUSCAN] on
        [EPOLeafNode].[AutoID] = [EPOProdPropsView_VIRUSCAN].[LeafNodeID]
        left join [EPOComputerProperties] on
        [EPOLeafNode].[AutoID] = [EPOComputerProperties].[ParentID]
        left join [EPOEventFilterDesc] on
        [EPOEvents].[ThreatEventID] = [EPOEventFilterDesc].[EventId]
        AND (EPOEventFilterDesc.Language='0409')

        /* Retrieve all data since the previous week */
WHERE ReceivedUTC >= DATEADD(week, -1, GETUTCDATE())
        /* Will retrieve the IDs that were not retrieved during last query */
        AND [EPOEvents].[AutoID] > :sql_last_value
        /* Threat Security less than 3 are Critical and Alert */
        AND [EPOEvents].[ThreatSeverity] < 3
        /* Solidifier, a white listing application product, has too many notifications.*/
        AND [EPOEvents].[AnalyzerName] <> 'Solidifier'
        /* The 'Data Loss Prevention' Application registers too much data, such as plugging in USB devices.*/
        AND [EPOEvents].[AnalyzerName] <> 'Data Loss Prevention'

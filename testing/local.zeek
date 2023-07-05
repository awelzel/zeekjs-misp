# For testing...
redef MISP::url = "https://localhost:443";
redef MISP::api_key = getenv("MISP_API_KEY");
redef MISP::insecure = T;
redef MISP::refresh_interval = 30sec;

# Pull data from these fixed events representing feeds:
#
# TODO: Support wild-card import.
redef MISP::fixed_events += {
    1243,  # tor exit nodes feed.
    1294,  # URLHaus Malware URLs feed
    1296,  # tor all nodes feed
    1295,  # threatfox
};

# Convenience.
redef LogAscii::use_json = T;



# Enable intel seen and report any hosts.
@load frameworks/intel/seen

# This is for testing all connections, but it causes duplicate intel
# matches per connection, too.
#
# event new_connection(c: connection) {
#	Intel::seen([$host=c$id$orig_h, $conn=c, $where=Conn::IN_ORIG]);
#	Intel::seen([$host=c$id$resp_h, $conn=c, $where=Conn::IN_RESP]);
#}

# Log the loaded intel data on a regular basis.
module Intel;
# hook Telemetry::sync() {
	# print  "min_data_store host_data", |Intel::data_store$host_data|, |Intel::min_data_store$host_data|;
	# print  "min_data_store subnet_data", |Intel::data_store$subnet_data|, |Intel::min_data_store$subnet_data|;
	# print  "min_data_store string_data", |Intel::data_store$string_data|, |Intel::min_data_store$string_data|;

	# print Intel::data_store$host_data;
	# print Intel::data_store$string_data;
# }

@load base/frameworks/cluster
@load base/frameworks/intel

module MISP;

export {
	## URL to MISP server. HTTPS required.
	const url: string = "" &redef;

	## API key for the MISP server.
	const api_key: string = "" &redef;

	## Allow self-signed certificate for testing.
	const insecure: bool = F &redef;

	## Interval to query and refresh Intel data.
	const refresh_interval = 2 mins &redef;

	## Fixed event IDs to load attributes from.
	##
	## Queries all attributes of these events and populates
	## the Intel framework.
	##
	## TODO: Not sure this is very useful when having
	##       the generic search.
	const fixed_events: set[count] = {} &redef;

	## Use the following tags as a filter. Use "!tag" for negation.
	const attributes_search_tags: vector of string &redef;

	## Use the following event ids (strings) as a filter. Use "!eventid"
	## for negation.
	const attributes_search_event_ids: vector of string &redef;

	## Filter by attribute types. Use "!type" to negate.
	##
	## Examples: ip-src, ip-dst, md5, sha1, ...
	const attributes_search_types: vector of string &redef;

	## Interval to go back to search for attributes within MISP.
	## When set to 0days, no time range restriction applies.
	const attributes_search_interval = 90days;

	## Report this many sightings per attribute back to MISP
	## over a period of max_item_sightings_interval.
	const report_sightings = T &redef;

	## Report this many sightings per attribute back to MISP
	## over a period of max_item_sightings_interval.
	const max_item_sightings = 5 &redef;

	## Interval for max_item_sightings to avoid
	## flooding with sightings.
	const max_item_sightings_interval = 5secs &redef;
}


redef record Intel::MetaData += {
	misp_event_id: count &optional;
	misp_attribute_uid: string &optional;
	report_sightings: bool &default = F;
};


# Only run JavaScript functionality on the manager process.
#
# 1) Queries the MISP server for events and aattributes and populates
#    the intel framework.
# 2) Distributes Intel data to the workers
# 3) Report sigthings back to MISP by handling Intel::match() events.
#
@if ( ! Cluster::is_enabled() || Cluster::local_node_type() == Cluster::MANAGER )
@ifdef ( JavaScript )
@load ./zeek-misp.js
@else
event zeek_init() {
	Reporter::error("Missing JavaScript support");
}
@endif
@endif

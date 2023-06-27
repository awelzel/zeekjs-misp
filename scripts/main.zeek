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
	const fixed_events: set[count] = {} &redef;

	## Use the following tags as a filter. Use "!tag" for negation.
	const attributes_search_tags: vector of string &redef;

	## Interval to go back to search for attributes
	## within MISP.
	const attributes_search_interval = 90days;

	## Report this many sightings back to MISP
	## in max_item_sightings_interval.
	const max_item_sightings = 5 &redef;

	## Interval for max_item_sightings to avoid
	## reporting too many sightings.
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
@load ./zeek-misp.js
@endif

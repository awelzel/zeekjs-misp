@load base/frameworks/cluster
@load base/frameworks/intel

module MISP;

export {
	## URL to MISP server. HTTPS required.
	option url: string = "";
	option api_key: string = "";
	## Allow self-signed certificate.
	option insecure: bool = F;

	## Interval query and refresh metadata.
	option refresh_interval = 2 mins;

	## Fixed events to load attributes from
	option fixed_events: set[count] = {};
}


redef record Intel::MetaData += {
	misp_event_id: count &optional;
	misp_attribute_uid: string &optional;
	report_sightings: bool &default = F;
	matches: count &default=0;
	# TODO: Track heavy hitters (see threatbus approach)
};


# Only run JavaScript functionality on the manager
#
# 1) Load data via MISP events/attributes.
# 2) Distributes Intel data to the workers
# 3) Report sigthings back to MISP by handling Intel::match event.
#
@if ( ! Cluster::is_enabled() || Cluster::local_node_type() == Cluster::MANAGER )
@load ./zeek-misp.js
@endif

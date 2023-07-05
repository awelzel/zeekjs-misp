# zeek-js-misp

Implementation of a package similar to the [dovehawk](https://github.com/tylabs/dovehawk) package,
but using JavaScript instead of ActiveHTTP.

## Requirements

This package requires a Zeek installation with JavaScript enabled
either by installing the external ZeekJS plugin, or using a Zeek
version with it built-in.

## Features

* The manager process in a Zeek cluster regularly fetches event attributes
  from a MISP instance and populates the Intel framework using
  `Intel::insert()`. Current assumption is that the MISP API is
  available.

* Upon `Intel::match()` events, the manager process reports back
  [sightings](https://www.circl.lu/doc/misp/sightings/) to the
  MISP instance.


## Fetching of attributes

### Fixed events

In MISP, certain streams are imported as fixed events. IDs of such events
can be specified in ``MISP::fixed_events`` to import all indicators of such
events into Zeek.

For example, the ALL tor nodes stream may be imported as a fixed event.

### Attributes search

The alternative to fixed events is to search for all attributes on the MISP
instance in a certain time range, tags or types.  By default, all attributes
created in the past 90 days that have the ``to_ids`` flag set are fetched.

For more fine-grained customization, currently The options `MISP::attributes_search_tags`,
`MISP::attributes_search_event_ids`, `MISP::attributes_search_types` and
`MISP::attributes_search_interval` can be used to control this behavior.

For example, to ignore attributes of type MD5 and SHA1 hashes, extend the
following option with the negated types:

    redef MISP::attributes_search_types += {"!md5", "!sha1"}'

## Example usage

Testing with a local [MISP docker-compose setup](https://github.com/MISP/misp-docker),
first create an API key for the user, export it as `MISP_API_KEY` into the
environment had configure ``local.zeek`` as follows:

    redef MISP::url = "https://localhost:443";
    redef MISP::api_key = getenv("MISP_API_KEY");
    redef MISP::insecure = T;
    redef MISP::refresh_interval = 30sec;
    redef MISP::debug = T;


If you have MISP events that hold attributes that ``zeek-js-misp`` should
ingest regardless of a time range, use ``MISP::fixed_events``. This can be
useful if feeds of hashes or IPs are loaded into the same fixed event.

    redef MISP::fixed_events += { 1234 }


## Open topics

* Current poll interval is 2 minutes resulting in an import delay for newly
  created attributes and extra search overhead on a regular basis.

* Data is not deleted from the Intel framework.

Both could be approached using ZeroMQ bindings with MISP and act on creation
and deletion of attributes. On the other hand, a regular export of Intel data
from MISP via a cron job has a similar issue.

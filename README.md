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
instance in a certain time range, tags or types. The options
`MISP::attributes_search_tags`, `MISP::attributes_search_event_ids`,
`MISP::attributes_search_types` and `MISP::attributes_search_interval`
can be used to control this behavior.

## Example usage

Testing with a local MISP container instance:

    redef MISP::url = "https://localhost:443";
    redef MISP::api_key = getenv("MISP_API_KEY");
    redef MISP::insecure = T;
    redef MISP::refresh_interval = 30sec;

    redef MISP::fixed_events += {
        1243,  # tor ALL nodes feed
    };

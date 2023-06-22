# zeek-js-misp

Implementation of a package similar to the [dovehawk](https://github.com/tylabs/dovehawk) package
but using JavaScript.


    zeek ./scripts/ MISP::url="https://localhost" MISP::api_key="your API key"


Do not forget to load frameworks/intel/seen!


## Fixed events

In MISP, certain streams are imported as fixed events. Using
``MISP::fixed_events`` allows to import all indicatorsof such events.

For example, Tor exit nodes, malware hashes or domain lists.


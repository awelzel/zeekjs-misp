const misp = require('./misp');

// Read some redefs from the Zeek side into globals
const refreshIntervalMilliSeconds = zeek.global_vars['MISP::refresh_interval'] * 1000;
const maxItemSightings = zeek.global_vars['MISP::max_item_sightings'];
const maxItemSightingsIntervalMilliseconds = zeek.global_vars['MISP::max_item_sightings_interval'] * 1000;

let refreshRunning = false;
let mispObj = null;

const mispTypeToIntelType = {
  'ip-dst': 'Intel::ADDR',
  'ip-src': 'Intel::ADDR',
  domain: 'Intel::DOMAIN',
  // good enough?
  hostname: 'Intel::DOMAIN',
  filename: 'Intel::FILE_NAME',
  md5: 'Intel::FILE_HASH',
  sha1: 'Intel::FILE_HASH',
  sha256: 'Intel::FILE_HASH',
  sha512: 'Intel::FILE_HASH', // no native support in Zeek
  url: 'Intel::URL',
  'email-src': 'Intel::EMAIL',

  // That is pretty annoying...
  'ip-dst|port': 'Intel::ADDR',

  // TODO: These would need to be split up in to intel items presumably.
  // 'domain|ip', 'filename|sha1',
};

const mispTypesIgnored = new Set([
  'yara',
  'malware-sample',
  'ssdeep',
  'pattern-in-traffic',
]);

function mungeMispValue(t, v) {
  if (t === 'url') { return v.replace(/^https?:\/\//, ''); }

  // ip-dst|port 207.148.99.121|9000
  //
  // Not sure if ignoring the port is okay: We may need to post-process
  // the intel match and check for id$resp_p? This could get a bit
  // hairy unless we make it explicit in the metadata.
  if (t === 'ip-dst|port') { return v.split('|')[0]; }

  return v;
}

// Given a list of attributes, return Intel items to be inserted into
// the intel framework.
function attributesAsIntelItems(attributes) {
  return attributes.reduce((items, attr) => {
    const eventId = attr.Event.id;
    const meta = {
      source: `MISP-${eventId}`,
      desc: JSON.stringify(attr.Event),
      url: `${mispObj.url}/events/view/${eventId}`,
      report_sightings: true,
      misp_event_id: parseInt(eventId, 10),
      misp_attribute_uid: attr.uuid,
    };

    const intelType = mispTypeToIntelType[attr.type];
    if (intelType !== undefined) {
      const intelItem = {
        indicator: mungeMispValue(attr.type, attr.value),
        indicator_type: intelType,
        meta,
      };
      items.push(intelItem);
    } else if (!mispTypesIgnored.has(attr.type)) {
      console.warn('IGNORING', attr.type, attr.value);
    }

    return items;
  }, []);
}

function insertIntelItem(item) {
  zeek.invoke('Intel::insert', [item]);
}

// Search for attributes with the to_ids flags set to 1 and
// some configurable filters.
async function searchAttributes() {
  let start = performance.now();

  const tags = zeek.global_vars['MISP::attributes_search_tags'];
  let eventIds = zeek.global_vars['MISP::attributes_search_event_ids'];
  const attrTypes = zeek.global_vars['MISP::attributes_search_types'];

  // Remove fixedEvents from attribute search.
  const fixedEvents = zeek.global_vars['MISP::fixed_events'];
  eventIds = eventIds.concat(fixedEvents.map((e) => `!${e}`));

  // We could just ignore fixed types here.
  const search = {
    tags,
    to_ids: 1,
    eventid: eventIds,
    type: attrTypes,
  };

  // Set "from" field to unix timestamp if attributes_search_interval is given.
  const interval = zeek.global_vars['MISP::attributes_search_interval'];
  if (interval > 0) {
    search.from = Math.floor(new Date().getTime() / 1000) - interval;
  }

  console.log(`Attribute search ${JSON.stringify(search)}`);

  const attributes = await mispObj.attributesRestSearch(search);
  const requestMs = performance.now() - start;
  start = performance.now();

  const intelItems = attributesAsIntelItems(attributes);
  intelItems.forEach(insertIntelItem);
  const insertMs = performance.now() - start;
  console.log(`searchAttributes done items=${intelItems.length} requestMs=${requestMs}ms insertMs=${insertMs}ms`);
}

// Fetch all attributes of a single event.
async function refreshEvent(eventId) {
  let start = performance.now();
  const attributes = await mispObj.attributesRestSearch({
    eventid: eventId.toString(),
  });

  const requestMs = performance.now() - start;
  start = performance.now();

  if (attributes.length > 0) {
    const intelItems = attributesAsIntelItems(attributes);

    intelItems.forEach(insertIntelItem);

    const insertMs = performance.now() - start;
    console.log(`refreshEvent ${eventId} done items=${intelItems.length} requestMs=${requestMs}ms insertMs=${insertMs}ms`);
  }
}

async function refreshIntel() {
  // Schedule refreshes without drift. Skip a refresh
  // when the previous one is still running.
  console.log(`Schedule for ${refreshIntervalMilliSeconds}...`);
  setTimeout(refreshIntel, refreshIntervalMilliSeconds);
  if (refreshRunning) { return; }

  refreshRunning = true;

  // Not sure fixed events makes sense if we can use generic attributes
  const fixedEvents = zeek.global_vars['MISP::fixed_events'];
  if (fixedEvents.length > 0) {
    console.log(`Loading intel data for fixed events ${fixedEvents}`);

    const pendingPromises = fixedEvents.map(refreshEvent);
    await Promise.all(pendingPromises).catch((reason) => {
      console.error('Failed to fetch fixed events:', reason);
    });
    console.log('Fixed events done');
  }

  console.log('Loading intel data through attributes search');
  await searchAttributes().catch((reason) => {
    console.error('Failed search attributes:', reason);
  });
  console.log('Attributes search done');
  refreshRunning = false;
}

zeek.on('zeek_init', () => {
  console.log('Starting up zeek-js-misp');
  console.log('url', zeek.global_vars['MISP::url']);
  console.log('api_key', `${zeek.global_vars['MISP::api_key'].slice(0, 4)}...`);
  console.log('refresh_interval', refreshIntervalMilliSeconds);
  console.log('max_item_sightings', maxItemSightings);
  console.log('max_item_sightings_interval', maxItemSightingsIntervalMilliseconds);

  mispObj = new misp.MISP(
    zeek.global_vars['MISP::url'],
    zeek.global_vars['MISP::api_key'],
    zeek.global_vars['MISP::insecure'],
  );

  // Start refreshing intel right after startup.
  setImmediate(refreshIntel);
});

// eslint-disable-next-line
BigInt.prototype.toJSON = function () {
  return this.toString();
};

const mispHits = new Map();

// Handle Intel::match events and report them back to the
// MISP instance  as sightings.
async function handleIntelMatch(seen, items) {
  console.log('zeek-misp: Intel::match', seen.indicator);
  const now = Date.now();
  const pendingPromises = [];

  items.forEach((item) => {
    const { meta } = item;
    const attributeId = meta.misp_attribute_uid;

    if (meta.report_sightings && attributeId !== undefined) {
      let hitsEntry = mispHits.get(attributeId);

      // Create/reset hitsEntry if expired.
      if (hitsEntry === undefined || hitsEntry.ts < now - maxItemSightingsIntervalMilliseconds) {
        hitsEntry = { ts: now, hits: 0 };
        mispHits.set(attributeId, hitsEntry);
      }

      hitsEntry.hits += 1;
      if (hitsEntry.hits <= maxItemSightings) {
        pendingPromises.push(mispObj.addSightingAttribute(item.meta.misp_attribute_uid));
      } else {
        console.log(`Sighting rate limited ${item.indicator} - ${JSON.stringify(hitsEntry)}`);
      }
    }
  });

  // Wait for all the sigthings to finish.
  await Promise.all(pendingPromises).catch((r) => {
    console.error('ERROR: Sending sightings failed:', r);
  });
}

if (zeek.global_vars['MISP::report_sightings']) {
  zeek.on('Intel::match', { priority: -1 }, handleIntelMatch);
}

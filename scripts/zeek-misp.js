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
  md5: 'Intel::FILE_HASH',
  sha1: 'Intel::FILE_HASH',
  sha256: 'Intel::FILE_HASH',
  url: 'Intel::URL',

  // That is pretty annoying...
  'ip-dst|port': 'Intel::ADDR',
};

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

function attributesAsIntelItems(attributes, baseMeta) {
  return attributes.reduce((items, attr) => {
    const intelType = mispTypeToIntelType[attr.type];

    if (intelType !== undefined) {
      const intelItem = {
        indicator: mungeMispValue(attr.type, attr.value),
        indicator_type: intelType,
        meta: { ...baseMeta, misp_attribute_uid: attr.uuid },
      };
      items.push(intelItem);
    } else {
      console.log('IGNORING', attr.type, attr.value);
    }

    return items;
  }, []);
}

function insertIntelItem(item) {
  zeek.invoke('Intel::insert', [item]);
}

async function refreshEvent(eventId) {
  let start = performance.now();
  const attributes = await mispObj.attributesRestSearch({
    eventid: eventId.toString(),
  });

  const requestMs = performance.now() - start;
  start = performance.now();

  if (attributes.length > 0) {
    const baseMeta = {
      source: `MISP-${eventId}`,
      desc: JSON.stringify(attributes[0].Event),
      url: `${mispObj.url}/events/view/${eventId}`,
      report_sightings: true,
      misp_event_id: eventId,
    };

    const intelItems = attributesAsIntelItems(attributes, baseMeta);

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

  const fixedEvents = zeek.global_vars['MISP::fixed_events'];
  console.log(`Loading intel data for fixed events ${fixedEvents}`);

  const pendingPromises = fixedEvents.map(refreshEvent);
  await Promise.all(pendingPromises).catch((reason) => {
    console.error('Failed to fetch fixed events:', reason);
  });

  console.log('fixed events done');

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

  setImmediate(refreshIntel);
});

// eslint-disable-next-line
BigInt.prototype.toJSON = function () {
  return this.toString();
};

const mispHits = new Map();

// Report intel matches back to the MISP instance.
zeek.on('Intel::match', { priority: -1 }, async (seen, items) => {
  console.log('JS Intel::match', seen.where, items[0]);

  const pendingPromises = [];
  items.forEach((item) => {
    const { meta } = item;
    const attributeId = meta.misp_attribute_uid;

    if (meta.report_sightings && attributeId !== undefined) {
      const now = Date.now();
      let hitsEntry = mispHits.get(attributeId);

      console.log(`Current hits ${attributeId} ${JSON.stringify(hitsEntry)}`);

      // Create/reset hitsEntry if expired.
      if (hitsEntry === undefined || hitsEntry.ts < now - maxItemSightingsIntervalMilliseconds) {
        hitsEntry = { ts: now, hits: 0 };
        mispHits.set(attributeId, hitsEntry);
      }

      if (hitsEntry.hits < maxItemSightings) {
        pendingPromises.push(mispObj.addSightingAttribute(item.meta.misp_attribute_uid));
        hitsEntry.hits += 1;
      } else {
        console.log(`Sighting rate limited ${item.indicator} - ${hitsEntry}`);
      }
    }
  });

  // Wait for all the sigthings to finish.
  await Promise.all(pendingPromises).catch((r) => {
    console.error('ERROR: Sending sightings failed:', r);
  });
});

// zeek specific

const misp = require('./misp');

let refreshIntervalMilliSeconds = 120 * 1000;
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
  // the intel match and check for id$resp_p? Also, what protocol?!
  if (t === 'ip-dst|port') { return v.split('|')[0]; }

  return v;
}

function attributesAsIntelItems(attributes, baseMeta) {
  const r = [];
  attributes.forEach((attr) => {
    const intelType = mispTypeToIntelType[attr.type];

    if (intelType !== undefined) {
      const intelItem = {
        indicator: mungeMispValue(attr.type, attr.value),
        indicator_type: intelType,
        meta: { ...baseMeta, misp_attribute_uid: attr.uuid },
      };
      r.push(intelItem);
    } else {
      console.log('IGNORING', attr.type, attr.value);
    }
  });

  return r;
}

function insertIntelItem(item) {
  zeek.invoke('Intel::insert', [item]);
}

async function refreshEvent(eventId) {
  console.log('refreshEvent', eventId);
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

  // XXX: This is async!
  fixedEvents.forEach(refreshEvent);

  refreshRunning = false;
}

zeek.on('zeek_init', () => {
  console.log('Starting up zeek-js-misp');
  console.log('url', zeek.global_vars['MISP::url']);
  console.log('api_key', `${zeek.global_vars['MISP::api_key'].slice(0, 4)}...`);
  console.log('refresh_interval', `${zeek.global_vars['MISP::refresh_interval']}`);

  mispObj = new misp.MISP(
    zeek.global_vars['MISP::url'],
    zeek.global_vars['MISP::api_key'],
    zeek.global_vars['MISP::insecure'],
  );

  refreshIntervalMilliSeconds = zeek.global_vars['MISP::refresh_interval'] * 1000;

  setImmediate(refreshIntel);
});

// eslint-disable-next-line
BigInt.prototype.toJSON = function () {
  return this.toString();
};

// Report intel matches back to the MISP instance.
//
// TODO: Rate-limit heavy hitters.
zeek.on('Intel::match', { priority: -1 }, async (seen, items) => {
  console.log('JS Intel::match', JSON.stringify(seen), 'items', JSON.stringify(items));

  for (let i = 0; i < items.length; i += 1) {
    const item = items[i];
    const { meta } = items[i];

    // eslint-disable-next-line
    // meta.matches = meta.matches + 1n;
    console.log(zeek.invoke('type_name', [meta]));
    console.log(zeek.invoke('to_json', [meta]));

    if (item.meta.report_sightings && item.meta.misp_attribute_uid) {
      console.log('Sending sighting!');
      // eslint-disable-next-line
      await mispObj.addSightingAttribute(item.meta.misp_attribute_uid);
      console.log('Sighting sent');
    } else {
      console.log('NOPE');
    }
  }
});

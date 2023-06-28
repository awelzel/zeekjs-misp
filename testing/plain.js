const repl = require('node:repl');
const misp = require('../scripts/misp');

console.log(misp);

(async () => {
  const myMisp = new misp.MISP('https://localhost:443/', process.env.MISP_API_KEY, true);
  // console.log(myMisp.options);
  const attributes = await myMisp.attributesRestSearch({
    limit: 128,
    // to_ids: 1,
    // tor exit nodes
    eventid: 1294,
    from: '2023-06-01',
  });
  console.log(attributes);
  const types = attributes.map((a) => [a.type, a.value, a.to_ids]);
  console.log(types);

  const r = repl.start();
  r.context.attributes = attributes;
  r.context.myMisp = myMisp;
})();

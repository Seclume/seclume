// Checks CycloneDX documents against the official 1.6 JSON schema, offline:
// bom-1.6 and the SPDX licence list and JSF it refers to are in
// .github/schemas/cyclonedx. Each file is reported; any invalid one fails the
// run, with the paths that are wrong as annotations on the pull request.
//
// usage: node validate-cbom.mjs <file.json> [...]
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import Ajv from 'ajv';
import addFormats from 'ajv-formats';

const schemas = join(dirname(fileURLToPath(import.meta.url)), '..', 'schemas', 'cyclonedx');
const load = (name) => JSON.parse(readFileSync(join(schemas, name), 'utf8'));

// strict: false - the schema carries keywords of its own ("meta:enum").
const ajv = new Ajv({ strict: false, allErrors: true });
addFormats(ajv);
// Formats ajv-formats does not know; draft-07 treats unknown formats as annotations.
for (const format of ['iri-reference', 'idn-email']) {
  ajv.addFormat(format, true);
}
ajv.addSchema(load('spdx.schema.json'));
ajv.addSchema(load('jsf-0.82.schema.json'));
const validate = ajv.compile(load('bom-1.6.schema.json'));

const files = process.argv.slice(2);
if (files.length === 0) {
  console.error('usage: node validate-cbom.mjs <file.json> [...]');
  process.exit(2);
}
let failed = 0;
for (const file of files) {
  const document = JSON.parse(readFileSync(file, 'utf8'));
  if (validate(document)) {
    console.log(`${file}: valid CycloneDX ${document.specVersion}, `
      + `${(document.components || []).length} components`);
  } else {
    failed++;
    for (const error of validate.errors.slice(0, 20)) {
      console.log(`::error title=CBOM ${file}::${error.instancePath || '(root)'} `
        + `${error.message} ${JSON.stringify(error.params)}`.slice(0, 400));
    }
  }
}
process.exit(failed ? 1 : 0);

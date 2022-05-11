import fs from 'fs';
import tds from './td_check/trackers.js';
import tds_rules from './td_check/tds.json';
let lists = [tds_rules]
tds.setLists(lists)
const csvFile = process.argv.slice(2)[0];
import { readFileSync, writeFileSync } from 'fs';
import { dirname, resolve } from 'path';
import { fileURLToPath } from 'url';
import * as readline from 'node:readline'; 


const __dirname = dirname(fileURLToPath(import.meta.url));

async function read(path) {
    return readFileSync(resolve(__dirname, path), 'utf8');
}

(async () => {
    try {
        const { StaticNetFilteringEngine } = await import('@gorhill/ubo-core');
        const snfe = await StaticNetFilteringEngine.create();
        try {
            await snfe.useLists([
                read('./lists/badware.txt')
                    .then(raw => ({ name: 'badware', raw })),
                read('./lists/ublock_filters.txt')
                    .then(raw => ({ name: 'filters', raw })),
                read('./lists/ublock_abuse.txt')
                    .then(raw => ({ name: 'resource-abuse', raw })),
                read('./lists/ublock_privacy.txt')
                    .then(raw => ({ name: 'privacy', raw })),
                read('./lists/ublock_unbreak.txt')
                    .then(raw => ({ name: 'unbreak.txt', raw })),
                read('./lists/easylist.txt')
                    .then(raw => ({ name: 'easylist', raw })),
                read('./lists/easyprivacy.txt')
                    .then(raw => ({ name: 'easyprivacy', raw })),
                read('./lists/yoyo.txt')
                    .then(raw => ({ name: 'PGL', raw })),
                read('./lists/url_haus.txt')
                    .then(raw => ({ name: 'urlhaus', raw })),
            ]);
        } catch (error) {
            console.log(error)
        }

        let lines = []
        const file = readline.createInterface({
            input: fs.createReadStream(resolve(__dirname, '../csv') + '/' +csvFile),
            output: process.stdout,
            terminal: false
        });
        file.on('line', (line) => {
            let params = line.split('\t')
            let initial_hostname = params[7];
            if (initial_hostname !== 'initial_hostname') {
                let req_url = params[9]
                let req_type = params[26].toLowerCase()
                let ublock_result = snfe.matchRequest({
                    originURL: initial_hostname,
                    url: req_url,
                    type: req_type
                })
                let new_line = line + '\t' + ((ublock_result === 1) ? 'True' : 'False')
                let tds_result = tds.getTrackerData(req_url, initial_hostname, req_type)
                new_line += '\t' + ((tds_result !== null && tds_result.action==='block') ? 'True' : 'False')
                lines.push(new_line)
            }else{
                lines.push(line + '\t' +'ublock_blocked'+ '\t'+'tds_blocked')
            }
        });

        file.on('close', function () {
            const writeStream = fs.createWriteStream(resolve(__dirname,  '../csv') +  '/updated_' + csvFile);
            const pathName = writeStream.path;


            // write each value of the array on the file breaking line
            lines.forEach(value => writeStream.write(`${value}\n`));

            // the finish event is emitted when all data has been flushed from the stream
            writeStream.on('finish', () => {
                console.log(`wrote all the array data to file ${pathName}`);
            });

            // handle the errors on the write process
            writeStream.on('error', (err) => {
                console.error(`There is an error writing the file ${pathName} => ${err}`)
            });

            // close the stream
            writeStream.end();
        })
    } catch (e) {
        console.log(e);
    }
})();

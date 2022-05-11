const tds = require('../td_check/trackers')
const fs = require('fs');
let tds_rules = require('./tds');
let lists = [tds_rules]
tds.setLists(lists)


const readline = require('readline');
let lines = []
const file = readline.createInterface({
    input: fs.createReadStream("/home/asuman/Desktop/test_tracker/220128_additional_crawl_desktop_100k_no_action_nyc_leaks.csv"),
    output: process.stdout,
    terminal: false
});
file.on('line', (line) => {
    params = line.split('\t')
    let initial_hostname = params[7];
    if (initial_hostname !== 'initial_hostname') {
        let req_url = params[9]
        let req_type = params.at(-1).toLowerCase()
        let result = tds.getTrackerData(req_url, initial_hostname, req_type)
        let new_line = line + '\t' + ((result === null) ? 'not-block' : result.action)
        lines.push(new_line)
    }
});

file.on('close', function () {
    const fs = require('fs');
    const writeStream = fs.createWriteStream('220128_additional_crawl_desktop_100k_no_action_nyc_leaks_tds.csv');
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



const fs = require('fs');

function single_fn(dest) {
    if (dest === "") {
        dest = "tmp";
    }

    return function(req, _res, next, name){
        // if the destination directory does not exist, create it
        if (!fs.existsSync(dest)){
            fs.mkdirSync(dest, {recursive: true});
        }

        if (req === null || req.body === undefined || req.body === null){
            if (next !== undefined && next !== null){
                next();
            }
            return;
        }

        let file = req.body.file;
        if (file === undefined){
            if (next !== undefined && next !== null){
                next();
            }
            return;
        }

        // Check if file has a File constructor
        if (file.constructor.name !== 'File') {
            if (next !== undefined && next !== null){
                next();
            }
            return;
        }

        file.arrayBuffer().then((buffer) => {
            // Create a Uint8Array from the buffer
            const uint8Array = new Uint8Array(buffer);
          
            // Write the file to the destination directory
            const filePath = `${dest}/${file.name}`;
            fs.writeFileSync(filePath, uint8Array);
          
            // Set the file to the request body
            req.file = file;
          
            // Continue to the next middleware/handler
            if (next !== undefined || next !== null){
                next();
            }
          });
    }
}

function array_fn(dest){
    if (dest === "") {
        dest = "tmp";
    }

    return function(req, _res, next, name){
        if (!fs.existsSync(dest)){
            fs.mkdirSync(dest, {recursive: true});
        }

        if (req.body === undefined || req.body === null){
            if (next !== undefined && next !== null){
                next();
            }
            return;
        }

        let files = req.body.file;
        if (files === undefined){
            if (next !== undefined && next !== null){
                next();
            }
            return;
        }

        let fileArray = [];
        for (let file of files){
            if (file.constructor.name !== 'File') {
                continue;
            }

            file.arrayBuffer().then((buffer) => {
                const uint8Array = new Uint8Array(buffer);
                const filePath = `${dest}/${file.name}`;
                fs.writeFileSync(filePath, uint8Array);
                fileArray.push(file);
            });
        }

        req.files = fileArray;
        if (next !== undefined && next !== null){
            next();
        }
    };
}

function request_set_url(req, url) { 
    req.url = url;
}

function request_set_header(req, key, val) {
    req.setHeader(key, val);
}

function request_set_body(req, body) {
    req.body = body;
}

function request_get_url(req) {
    return req.url
}

function request_headers(req) { return req.headers }

function request_callbacks(req, res, next, process_data, process_content_type) {
    var body = '';
    req.on('data', (data) => {
        body += data.toString();
    })

    req.on('end', () => {
        const processed_data = JSON.parse(process_data(body));
        if (processed_data.response !== undefined && processed_data.response !== null ){
            const response =  processed_data.response;
            res.statusMessage = response.status_text;
            res.statusCode = response.status;
            return;
        }
        
        const request = processed_data.request;
        req.method = request.method;

        for (let key in request.headers) {
            if (request.headers.hasOwnProperty(key)) {
                value = exampleObj[key];
                req.setHeader(key, value);
            }
        }

        // Overwrite all response functions
        process_content_type(req, res, JSON.stringify(process_data.request));
        next();
    })
}

function response_add_header(res, key, val){ res.setHeader(key, val) }

function response_set_status(res, status) { res.statusCode = status }

function response_set_status_text(res, status_text) { res.statusMessage = status_text}

function response_set_body(res, body) { res.body = body }

function response_get_headers(res) {
    return res.headers
}

function response_get_status(res) {
    return res.statusCode
}

function response_get_status_text(res) {
    return res.statusMessage
}

function response_respond(res){}

function response_custom_json_fn(res) {}

function response_custom_send_fn(res) {}



module.exports = { 
    single_fn, array_fn,
    request_set_header, request_set_body, request_set_url, request_get_url, request_headers, request_callbacks,
    response_add_header, response_set_status, response_set_status_text, response_set_body, response_get_headers, response_get_status, response_get_status_text,
    response_custom_json_fn, response_custom_send_fn
};

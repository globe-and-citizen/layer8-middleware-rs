const fs = require('fs');

function single_fn(dest) {
  if (dest === '') {
    dest = 'tmp'
  }

  return function (req, _res) {
    // if the destination directory does not exist, create it
    if (!fs.existsSync(dest)) {
      fs.mkdirSync(dest, { recursive: true })
    }

    if (req === null || req.body === undefined || req.body === null) {
      return
    }

    // Create a Uint8Array from the buffer
    let file = JSON.parse(req.body).file;
    let data = Buffer.from(file.buff, "base64");

    // Write the file to the destination directory
    const filePath = `${dest}/${file.name}`
    fs.writeFileSync(filePath, data)

    // Set the file to the request body
    req.file = file

    // Continue to the next middleware/handler
    console.log("Successfully saved static file")
  }
}

// FIXME: this needs work
function array_fn(dest) {
  if (dest === '') {
    dest = 'tmp'
  }

  return function (req, _res) {
    if (!fs.existsSync(dest)) {
      fs.mkdirSync(dest, { recursive: true })
    }

    if (req.body === undefined || req.body === null) {
      return
    }

    let files = JSON.parse(req.body).files
    if (files === undefined) {
      return
    }

    let fileArray = []
    for (let file of files) {
      // Create a Uint8Array from the buffer
      let data = Buffer.from(file.buff, "base64");

      // Write the file to the destination directory
      const filePath = `${dest}/${file.name}`
      fs.writeFileSync(filePath, data)

      fileArray = [...fileArray, file]
    }

    req.files = fileArray

    // Continue to the next middleware/handler
    console.log("Successfully saved static files")
  }
}

function path_exists(path) {
  return fs.existsSync(path)
}

function request_set_url(req, url) {
  req.url = url
}

function request_set_header(req, key, val) {
  req.setHeader(key, val)
}

function request_set_body(req, body) {
  req.body = body
}

function request_set_method(req, method) {
  req.method = method
}

function request_get_url(req) {
  return req.url
}

function request_headers(req) {
  return req.headers
}

function request_get_body_string(req) {
  return JSON.stringify(req.body)
}

function request_callbacks(res, sym_key, mp_jwt, respond_callback) {
  res.send = function (obj) {
    respond_callback(res, obj, sym_key, mp_jwt)
  }

  res.json = function (obj) {
    respond_callback(res, obj, sym_key, mp_jwt)
  }
}

function request_add_on_end(req, end) {
  req.on('end', end)
}

function as_json_string(obj) {
  return JSON.stringify(obj)
}

function response_add_header(res, key, val) {
  res.setHeader(key, val)
}

function response_set_status(res, status) {
  res.statusCode = status
}

function response_set_status_text(res, status_text) {
  res.statusMessage = status_text
}

function response_set_body(res, body) {
  res.body = body
}

function response_get_headers(res) {
  return res.headers
}

function response_get_status(res) {
  return res.statusCode
}

function response_get_status_text(res) {
  return res.statusMessage
}

function response_end(res, data) {
  res.end(data)
}

// FIXME: hacked around and settled on this
function get_url_path(js_str) {
  const val = JSON.parse(js_str);
  return JSON.parse(val).__url_path
}

module.exports = {
  single_fn,
  array_fn,
  path_exists,
  as_json_string,
  request_set_header,
  request_set_body,
  request_set_url,
  request_set_method,
  request_get_url,
  request_headers,
  request_callbacks,
  request_get_body_string,
  request_add_on_end,
  response_add_header,
  response_set_status,
  response_set_status_text,
  response_set_body,
  response_get_headers,
  response_get_status,
  response_get_status_text,
  response_end,

  get_url_path
}

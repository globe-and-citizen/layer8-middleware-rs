const fs = require('fs');

function single_fn(dest, decompress_fn) {
  if (dest === '') {
    dest = 'tmp'
  }

  // This higher order function is used to dynamically provide the filename
  return function (filename) {
    // This is the middleware function that will be used to save the file
    return function (req, _res) {
      // if the destination directory does not exist, create it
      if (!fs.existsSync(dest)) {
        fs.mkdirSync(dest, { recursive: true })
      }

      if (req === null || req.body === undefined || req.body === null) {
        call_next(arguments)
        return
      }

      // Create a Uint8Array from the buffer
      req.body = uint8ArrayToString(req.body)
      let file = JSON.parse(req.body)[filename];
      let data = decompress_fn(file.buff);

      // Write the file to the destination directory
      const filePath = `${dest}/${file.name}`
      fs.writeFileSync(filePath, data)

      // Set the file to the request body
      req.file = file

      // Continue to the next middleware/handler
      console.log("Successfully saved static file")
      call_next(arguments)
    }
  }
}

function array_fn(dest, decompress_fn) {
  if (dest === '') {
    dest = 'tmp'
  }

  // This higher order function is used to dynamically provide the filename
  return function (fileCollectionName) {
    // This is the middleware function that will be used to save the file
    return function (req, _res) {
      if (!fs.existsSync(dest)) {
        fs.mkdirSync(dest, { recursive: true })
      }

      if (req.body === undefined || req.body === null) {
        call_next(arguments)
        return
      }

      req.body = uint8ArrayToString(req.body)
      let files = JSON.parse(req.body)[fileCollectionName]
      if (files === undefined) {
        call_next(arguments)
        return
      }

      let fileArray = []
      for (let file of files) {
        if (file.constructor.name !== 'File') {
          continue
        }

        let data = decompress_fn(file.buff)
        const filePath = `${dest}/${file.name}`
        fs.writeFileSync(filePath, data)
        fileArray.push(file)
      }

      req.files = fileArray

      // Continue to the next middleware/handler
      console.log("Successfully saved static files")
      call_next(arguments)
    }
  }
}

function call_next(args) {
  // we expect an overload on the third argument to be next middleware call
  if (args.length >= 3) {
    if (args[2]) {
      args[2]()
    }
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

function uint8ArrayToString(data) {
  if (data instanceof Uint8Array) {
    const uint8Array = new Uint8Array(data)
    const decoder = new TextDecoder();
    const string_ = decoder.decode(uint8Array)
    return string_
  }

  return data
}

function request_set_body(req, body) {
  if (req.headers["content-type"] === "application/json") {
    body = uint8ArrayToString(body)
  }

  req.body = body
}

function request_set_method(req, method) {
  req.method = method
}

function request_headers(req) {
  return req.headers
}

function request_get_body(req) {
  return req.body
}

function request_callbacks(res, sym_key, mp_jwt, respond_callback) {
  res.send = function (obj) {
    respond_callback(res, obj, sym_key, mp_jwt)
  }

  res.json = function (obj) {
    respond_callback(res, obj, sym_key, mp_jwt)
  }
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

function response_set_body_end(res, body) {
  res.end(body)
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

module.exports = {
  single_fn,
  array_fn,
  path_exists,
  as_json_string,
  request_set_header,
  request_set_body,
  request_set_url,
  request_set_method,
  request_headers,
  request_callbacks,
  request_get_body,
  response_add_header,
  response_set_status,
  response_set_status_text,
  response_set_body,
  response_set_body_end,
  response_get_headers,
  response_get_status,
  response_get_status_text,
}

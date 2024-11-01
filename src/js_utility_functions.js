const fs = require('fs')

function single_fn (dest) {
  if (dest === '') {
    dest = 'tmp'
  }

  return function (req, _res, next, name) {
    // if the destination directory does not exist, create it
    if (!fs.existsSync(dest)) {
      fs.mkdirSync(dest, { recursive: true })
    }

    if (req === null || req.body === undefined || req.body === null) {
      if (next !== undefined && next !== null) {
        next()
      }
      return
    }

    let file = req.body.file
    if (file === undefined) {
      if (next !== undefined && next !== null) {
        next()
      }
      return
    }

    // Check if file has a File constructor
    if (file.constructor.name !== 'File') {
      if (next !== undefined && next !== null) {
        next()
      }
      return
    }

    file.arrayBuffer().then(buffer => {
      // Create a Uint8Array from the buffer
      const uint8Array = new Uint8Array(buffer)

      // Write the file to the destination directory
      const filePath = `${dest}/${file.name}`
      fs.writeFileSync(filePath, uint8Array)

      // Set the file to the request body
      req.file = file

      // Continue to the next middleware/handler
      if (next !== undefined || next !== null) {
        next()
      }
    })
  }
}

function array_fn (dest) {
  if (dest === '') {
    dest = 'tmp'
  }

  return function (req, _res, next, name) {
    if (!fs.existsSync(dest)) {
      fs.mkdirSync(dest, { recursive: true })
    }

    if (req.body === undefined || req.body === null) {
      if (next !== undefined && next !== null) {
        next()
      }
      return
    }

    let files = req.body.file
    if (files === undefined) {
      if (next !== undefined && next !== null) {
        next()
      }
      return
    }

    let fileArray = []
    for (let file of files) {
      if (file.constructor.name !== 'File') {
        continue
      }

      file.arrayBuffer().then(buffer => {
        const uint8Array = new Uint8Array(buffer)
        const filePath = `${dest}/${file.name}`
        fs.writeFileSync(filePath, uint8Array)
        fileArray.push(file)
      })
    }

    req.files = fileArray
    if (next !== undefined && next !== null) {
      next()
    }
  }
}

function request_set_url (req, url) {
  req.url = url
}

function request_set_header (req, key, val) {
  req.setHeader(key, val)
}

function request_set_body (req, body) {
  req.body = body
}

function request_get_url (req) {
  return req.url
}

function request_headers (req) {
  return req.headers
}

function request_get_body_string (req) {
  return JSON.stringify(req.body)
}

function request_callbacks (res, next, sym_key, mp_jwt, respond_callback) {
  res.send = function (obj) {
    respond_callback(res, obj, sym_key, mp_jwt)
  }

  res.json = function (obj) {
    respond_callback(res, obj, sym_key, mp_jwt)
  }

  next()
}

function as_json_string (obj) {
  return JSON.stringify(obj)
}

function response_add_header (res, key, val) {
  res.setHeader(key, val)
}

function response_set_status (res, status) {
  res.statusCode = status
}

function response_set_status_text (res, status_text) {
  res.statusMessage = status_text
}

function response_set_body (res, body) {
  res.body = body
}

function response_get_headers (res) {
  return res.headers
}

function response_get_status (res) {
  return res.statusCode
}

function response_get_status_text (res) {
  return res.statusMessage
}

function response_end (res, data) {
  res.end(data)
}

module.exports = {
  single_fn,
  array_fn,
  as_json_string,
  request_set_header,
  request_set_body,
  request_set_url,
  request_get_url,
  request_headers,
  request_callbacks,
  request_get_body_string,
  response_add_header,
  response_set_status,
  response_set_status_text,
  response_set_body,
  response_get_headers,
  response_get_status,
  response_get_status_text,
  response_end
}

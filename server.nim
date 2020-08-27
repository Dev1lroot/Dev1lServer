import os, osproc, json, times, nre, unicode, strutils, rdstdin, system, terminal, asynchttpserver, asyncdispatch

echo "DEV1LSERVER v1.1"

type
  KeyVal = tuple[key, val: string]

var server = newAsyncHttpServer()
proc cb(req: Request) {.async.} =

  echo "REQUEST:"

  var variables: seq[KeyVal]

  proc newVariable(k,v:string): KeyVal =
    var o: KeyVal
    o.key = k
    o.val = v
    return o

  variables.add(newVariable("address",req.hostname))

  var default_h = newHttpHeaders([("Content-Type","text/html")])
  var locations: JsonNode
  var minify, firewall = false
  var limit, interval = 0

  if(existsFile("server.json")):
    var json = readFile("server.json")
    try:
      var settings = parseJson(json)
      locations = settings["locations"]
      minify = settings["options"]["minifier"].getBool()
      firewall = settings["options"]["firewall"].getBool()
      if firewall:
        limit = settings["firewall"]["limit"].getInt()
        interval = settings["firewall"]["interval"].getInt()
    except:
      stdout.styledWrite(fgRed, "server.json corrupter or damaged, default settings has been applied" & "\n")
  else:
    stdout.styledWrite(fgRed, "server.json is not found, default settings has been applied" & "\n")

  var get = req.url.query
  if (get != ""):
    stdout.styledWrite(fgWhite, "> ")
    stdout.styledWrite(fgBlue, req.hostname)
    stdout.styledWrite(fgWhite, " -> ")
    stdout.styledWrite(fgGreen, "GET")
    stdout.styledWrite(fgWhite, "      -> ")
    stdout.styledWrite(fgYellow, get & "\n")
    var key = get.split("=")[0]
    var value = get.split("=")[1]

  var post = req.body
  if (post != ""):
    stdout.styledWrite(fgWhite, "> ")
    stdout.styledWrite(fgBlue, req.hostname)
    stdout.styledWrite(fgWhite, " -> ")
    stdout.styledWrite(fgGreen, "POST")
    stdout.styledWrite(fgWhite, "     -> ")
    stdout.styledWrite(fgYellow, post & "\n")

  var location = req.url.path
  if (location != ""):
    stdout.styledWrite(fgWhite, "> ")
    stdout.styledWrite(fgBlue, req.hostname)
    stdout.styledWrite(fgWhite, " -> ")
    stdout.styledWrite(fgGreen, "LOCATION")
    stdout.styledWrite(fgWhite, " -> ")
    stdout.styledWrite(fgYellow, location & "\n")
  
  var files: seq[string]
  var folders: seq[string]

  proc trim(str: string): string =
    var output = str
    while(output.contains("  ")):
      output = output.replace("  "," ")
    while($output[0] == " "):
      output = output[1..^1]
    while($output[^1] == " "):
      output = output[0..output.len-2]
    return output

  proc d1_include(html, origin: string): string =
    stdout.write "  --  include: `"
    var i = trim(html)
    i = i.replace("{"," ")
    i = i.replace("}"," ")
    i = i.replace("@include:"," ")
    i = i.replace(re"[^A-Za-z0-9-_.]","")
    i = trim(i)
    i = "www"&origin&i
    i = $i
    stdout.write i
    if(existsFile(i)):
      stdout.write "` ...(done)!\n"
      return readFile(i)
    else:
      stdout.write "` ...(missing)!\n"
      return "<error>file at `"&i&"` not found</error>"

  proc d1_html_minifier(html: string): string =
    var newhtml = html
    newhtml = newhtml.replace(re"[\n\r\t]","")
    return newhtml

  proc d1_setval(html: string): string =
    var newhtml = html
    var newnewhtml = html
    for v in variables:
      for match in html.findIter(re("({)(\\s*|)(\\$"&v.key&")(\\s*|)(})")):
        stdout.write "  --  setval:  `"&v.key&"` -> `"&v.val&"`\n"
        newhtml = newhtml.replace(html[match.matchBounds],v.val)
    newnewhtml = newhtml
    for match in newhtml.findIter(re("({)(\\s*|)(\\$[A-Za-z0-9-_.]*)(\\s*|)(})")):
      var thiskey = newhtml[match.matchBounds].replace(re"[^A-Za-z0-9-_.]","")
      newnewhtml = newnewhtml.replace(newhtml[match.matchBounds],"")
      stdout.write "  --  setval:  `"&thiskey&"` -> UNDEFINED\n"
    return newnewhtml

  proc d1_parse(html, origin: string): string =
    var newhtml = html
    for match in html.findIter(re"({)(\s*|)(@include:)(\s*|)[A-Za-z0-9-._]*(\s*|)(})"):
      newhtml = newhtml.replace(html[match.matchBounds],d1_include(html[match.matchBounds],location))
      if newhtml.contains(re("({)(\\s*|)(\\$[A-Za-z0-9-_.]*)(\\s*|)(})")):
        newhtml = d1_setval(newhtml)
    return newhtml

  proc recursiveFileSearch(root: string) =
    for kind, path in walkDir(root):
      if(kind != pcDir):
        files.add(path)
      else:
        folders.add(path)

  proc passServerAddress(address: string): string =
    var dirs = address.split("/");
    var output = ""
    for index, dir in dirs:
      if (index != 0):
        output &= "/"&dir;
    return output

  proc passExtension(ext: string): string =
    var all = ext.split(".");
    return all[^1]

  proc getRequest(requestedMethod: string, requestedKey: string): string =
    var valueToReturn = "undefined"
    var source: string
    var rm = requestedMethod.toLowerAscii()
    if (get != "" and rm == "get"):
      source = get
    if (post != "" and rm == "post"):
      source = post
    if (source.contains("&")):
      var requests = split(source, '&')
      for request in requests:
        if (request.contains("=")):
          var key = request.split("=")[0]
          var value = request.split("=")[1]
          if (key == requestedKey):
            if (value != ""):
              valueToReturn = value
    else:
      var request = source
      if (source.contains("=")):
        var key = source.split("=")[0]
        var value = source.split("=")[1]
        if (key == requestedKey):
          if (value != ""):
            valueToReturn = value
    return valueToReturn

  proc status(code: int, msg: string, headers: HttpHeaders) {.async.} =
    echo "RESPONCE:"
    var scode = $code
    case code:
      of 403:
        var message = "<h3>403 FORBIDDEN</h3><p>"&msg&"</p>"
        await req.respond(Http403, message, newHttpHeaders([("Content-Type","text/html")]))
      of 404:
        var message = "<h3>404 PAGE NOT FOUND</h3><p>"&msg&"</p>"
        await req.respond(Http404, message, newHttpHeaders([("Content-Type","text/html")]))
      else:
        await req.respond(Http200, msg, headers)
    stdout.styledWrite(fgWhite, "> ")
    stdout.styledWrite(fgBlue, req.hostname)
    stdout.styledWrite(fgWhite, " <- ")
    stdout.styledWrite(fgGreen, "STATUS")
    stdout.styledWrite(fgWhite, " <- ")
    stdout.styledWrite(fgYellow, scode & "\n")

  proc isset(requestedMethod: string, requestedKey: string): bool =
    if (getRequest(requestedMethod, requestedKey) != "undefined"):
      return true
    else:
      return false

  proc d1_is_in_locations(location: string): bool = 
    var ret = false
    for i in locations:
      if i["location"].getStr() == location:
        return true
    return ret

  proc d1_get_node_by_location(location: string): JsonNode = 
    for i in locations:
      if i["location"].getStr() == location:
        return i

  if firewall:
    #var unixtime: int = toUnix(getTime())
    var r = %*{
      "requests": 1,
      "lastdate": toUnix(getTime())
    }
    if(existsFile("config/modules/firewall/gateway.json")):
      var json = readFile("config/modules/firewall/gateway.json")
      try:
        var clients = parseJson(json)
        try:
          var client_requests = clients[req.hostname]["requests"].getInt();
          var client_lastdate = clients[req.hostname]["lastdate"].getInt();
          if client_requests >= limit:
            var timeout = client_lastdate + interval
            if timeout > toUnix(getTime()):
              await status(403,"TOO MANY REQUESTS",default_h)
              echo "[FIREWALL]: TOO MANY REQUESTS FROM THIS USER"
              echo "[FIREWALL]: NOW: ",toUnix(getTime()),", TIMEOUT: ",timeout
            else:
              echo "[FIREWALL]: TIMEOUT PROCEED"
              echo "[FIREWALL]: NOW: ",toUnix(getTime()),", TIMEOUT: ",timeout
              clients[req.hostname] = r
              writeFile("config/modules/firewall/gateway.json",$clients)
          else:
            r["requests"] = newJInt(client_requests + 1)
            clients[req.hostname] = r
            writeFile("config/modules/firewall/gateway.json",$clients)
        except:
          clients.add(req.hostname,r)
          writeFile("config/modules/firewall/gateway.json",$clients)
      except:
        echo "[ERROR]: Check firewall config"
    else:
      writeFile("config/modules/firewall/gateway.json","{}")

  if (location != ""):
    if(existsFile("www"&location)):
      var message = readFile("www"&location)
      var ext = passExtension("www"&location)
      var headers = newHttpHeaders([("Content-Type","text/html")])
      case ext:
        of "css":
          headers = newHttpHeaders([("Content-Type","text/css")])
        of "js":
          headers = newHttpHeaders([("Content-Type","text/javascript")])
        of "jpg":
          headers = newHttpHeaders([("Content-Type","image/jpg")])
        of "gif":
          headers = newHttpHeaders([("Content-Type","image/gif")])
        of "png":
          headers = newHttpHeaders([("Content-Type","image/png")])
        else:
          headers = newHttpHeaders([("Content-Type","text/html")])
      if ext == "json" or ext == "d1":
        await status(403,"",default_h)
      else:
        await status(200, message, headers)
    else:
      if(d1_is_in_locations(location)):
        var loc = d1_get_node_by_location(location)
        var message = ""
        try:
          message = readFile("www"&loc["template"].getStr())
          for v in variables:
            while(message.contains(re("({)(\\s*|)(\\$"&v.key&")(\\s*|)(})"))):
              message = d1_setval(message)
          while(message.contains(re"({)(\s*|)(@include:)(\s*|)[A-Za-z0-9-._]*(\s*|)(})")):
            message = d1_parse(message,location)
            if minify:
              message = d1_html_minifier(message)
          await status(200, message, default_h)
        except:
          await status(404,"",default_h)
      else:
        await status(403,"",default_h)
  else:
    await status(200,"OK",default_h)

waitFor server.serve(Port(80), cb)

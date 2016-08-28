'use strict';

const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const color = require("colors");

//constants

const ERR_ARGUMENT_NOT_DEFINED = [1000, "Argument %s is not defined."];
const ERR_ARGUMENT_IS_NULL = [1100, "Argument %s is NULL"];
const ERR_NOT_A_STRING = [2000, "Argument %s is not a string."]
const ERR_NOT_A_FUNCTION = [3000, "Argument %s is not a function."];
const ERR_NOT_AN_ARRAY = [3100, "Argument %s is not an array."];
const ERR_NOT_A_STR_ARRAY = [3100, "Argument %s is not an array of strings."];
const ERR_NAME_ALREADY_EXIST = [4000, "A storage with this the same [name %s] is already registered!"];
const ERR_STORAGE_NAME_NOT_FOUND = [5000, "No storage with name %s is registered."];
//
const STATE_UNINITIALIZED = "uninitialized";
const STATE_DISCOVERING = "discovering";
const STATE_DISCOVERED = "discovered";
const STATE_HASHING = "hashing";
const STATE_HASHED = "hashed";

const LIST_FILTER_EXCLUDE_SCAN_ERRORS = "exclude_errors";
const LIST_FILTER_ALL = "include_errors";
const LIST_FILTER_SCAN_ERRORS_ONLY = "only_errors";

const EVENT_DISCOVERED = STATE_DISCOVERED;
const EVENT_HASHED = STATE_HASHED;
const EVENT_FILES_PROCESSING = "processing_files";

const CHUNK_SIZE_100MB = 1024 * 1024 * 100;
const READ_FILE_BUF_SIZE = 65336 * 4; //256k

var global_storage = new Map();

var SECRET = process.env.HMAC_SECRET || "purdy";

// test the hmac existance

var g_hmac = (function () {
  // lets try 3 differrent hashes
  var rc;
  try {
    rc = crypto.createHmac("sha256", SECRET);
  } catch (e) {
    rc = null;
  }
  return rc;
})();

//
// create storage object (outside module), consist of ONE  or MORE directories to scan
// storage object has associated eventEmitters
// storage object has a unique name
// storage object is an a database called global_storage (not exported)
// after discovery also possible a background MD5 hash scan of files in storage
//

/**
   name (name storage like "books", "vacation photos", etc)
   tree << injected ( array of base dirs the base_dirs );
   state << injected (discovery, md5, etc)
   event_emitter  << injected
*/

/* generic utilities */
/* generic utilities */
/* generic utilities */

function flat_map(map) {
  var rc = [];

  function reduce(_map) {
    for (var entry of _map) {
      if (entry[0] === ".") {
        continue;
      }
      if (entry[1] instanceof Map) {
        reduce(entry[1]);
        continue;
      }
      rc.push(entry);
    }
  }
  reduce(map);
  return rc;
}

function assert_function(func, name) {
  if (!(func instanceof Function)) {
    let e = ERR_NOT_A_FUNCTION.splice(0);
    e[1].replace("%s", name);
    throw e;
  }

}

function assert_array(arr, name) {
  //console.log("arr,name", arr, name);
  if (!(arr instanceof Array)) {
    let e = ERR_NOT_AN_ARRAY.splice(0);
    e[1].replace("%s", name);
    throw e;
  }
}

function assert_string(str, name) {
  //console.log("str,name", str, name);
  if (typeof str != "string") {
    let e = ERR_NOT_A_STRING.splice(0);
    e[1].replace("%s", name);
    throw e;
  }
}

function assert_array_of_strings(arr_str, name) {
  assert_array(arr_str, name);
  let k = arr_str.filter((str) => {
    return (typeof str == "string");
  });
  if (k.length != arr_str.length) {
    let e = ERR_NOT_A_STR_ARRAY.slice(0);
    e[1].replace("%s", name);
    throw e;
  }
}

function assert_defined_and_not_null(arg, name) {
  var e = null;
  if (arg == undefined) {
    e = ERR_ARGUMENT_NOT_DEFINED.slice(0);
  } else if (!arg) {
    e = ERR_ARGUMENT_IS_NULL.slice(0);
  }
  if (e) {
    e.replace("%s", name);
    throw e;
  }
}

function in_arr(arr, value) {
  assert_array(arr);
  assert_defined_and_not_null(value);
  if (arr.indexOf(value) >= 0) {
    return true;
  }
  return false;
}

function promiseWrap() {
  var arr = Array.from(arguments);
  var func = arr[0];
  arr.splice(0, 1);
  return new Promise(function (res, rej) {
    func.call(func /* this */ , ...arr, function (err, ctx) {
      if (err) {
        rej(err);
      } else {
        res(ctx);
      }
    });
  });
}

/* storage management */
/* storage management */
/* storage management */

function count_files(map) {
  let rc = [0, 0];
  var mapIter = map[Symbol.iterator]();

  for (var entry of map) {
    if (entry[1] instanceof Map) {
      let result = count_files(entry[1]);
      rc[0] += result[0];
      rc[1] += result[1];
      continue;
    }
    if (entry[0] === ".") {
      continue; //skip
    }
    if (typeof entry[0] == "string" && entry[1]) {
      rc[0]++;
      rc[1] += entry[1].size || 0;
    }
  }
  return rc;
}

function file_processing(storage) {

  let name = storage.name;
  let file_count_to_do = storage.file_count_to_do;
  let file_count_done = storage.file_count_done;
  let set;

  switch (storage.state) {
  case STATE_DISCOVERING:
    storage.file_count_done++;
    if (storage.file_count_done % 10) {
      return; //skip
    }
    set = storage.processing_discovery;
    set.forEach((func, dummy, s) => {
      //callback
      process.nextTick(func,
        storage.error, {
          file_count_to_do,
          file_count_done,
          name
        });
    });
    break;
  case STATE_HASHING:
    set = storage.processing_hmac_hashing
    let files_being_processed = storage.files_being_processed;
    set.forEach((func, dummy, s) => {
      //callback
      process.nextTick(() => {
        func(storage.error, {
          file_count_to_do,
          file_count_done,
          files_being_processed,
          name,
          file_name: storage.key
        });
        if (storage.end_of_file) {
          files_being_processed.delete(storage.key);
        }
      });
    });
    break;
  default:
    return; //skip this
  }
}

function is_file_processing_done(storage) {

  let file_count_to_do = storage.file_count_to_do;
  let file_count_done = storage.file_count_done;

  let set = null;
  let name = storage.name;

  // call processing_xxx listeners one more time, then remove the listeners
  switch (storage.state) {
  case STATE_DISCOVERING:
    if (file_count_done != file_count_to_do) {
      return false; //not done yet
    }
    set = storage.processing_discovery;
    set.forEach((func, dummy, s) => {
      //callback
      process.nextTick(func,
        storage.error, {
          file_count_to_do,
          file_count_done,
          name
        });
    });
    set.clear();
    storage.state = STATE_DISCOVERED;
    set = storage.done_discovered;
    set.forEach((func, dummy, s) => {
      process.nextTick(() => {
        func(storage.error, {
          file_count_to_do,
          file_count_done,
          name
        });
      });
    });
    set.clear();
    break;
  case STATE_HASHING:
    set = storage.processing_hmac_hashing;
    set.clear();
    //
    set = storage.done_hmac;
    set.forEach((func, dummy, s) => {
      process.nextTick(() => {
        func({
          file_count_to_do,
          file_count_done,
          name
        });
      });
    });
    set.clear();
    storage.state = STATE_HASHED;
    break;
  default:
    //skip this
  }
  return true;
}

function get_storage(storage_name) {
  if (!storage_name) {
    throw [-2, "Argument [storage_name] has no set!"];
  }
  if (typeof storage_name != "string") {
    throw [-3, "Argument [storage_name] is NOT of type string!"];
  }

  let storage = global_storage.get(storage_name.toLowerCase());
  return storage;
}

function get_file_list(storage_name, options) {
  let defaults = Object.assign({
    filter: LIST_FILTER_ALL
  }, options);

  let storage = get_storage(storage_name);
  if (!storage) {
    return [];
  }

  let filter = defaults.filter;
  delete defaults.filter;
  //room for more filter definitions

  //catch all
  if (Object.keys(defaults) > 0) {
    throw [-2, "Invalid properties in options object [%1] in call to [getFileList]".replace("%1", defaults)];
  }

  if (!in_arr([LIST_FILTER_EXCLUDE_SCAN_ERRORS, LIST_FILTER_ALL, LIST_FILTER_SCAN_ERRORS_ONLY], filter)) {
    throw [-3, "Wrong filter value used:" + filter];
  }

  let rc = [];

  function reduce(map) {
    if (!(map instanceof Map)) {
      return;
    }
    let entries = Array.from(map.entries());

    for (let entry of entries) {
      let key = entry[0];
      let payl = entry[1];
      if (key === ".") {
        continue;
      }
      let sub_payl;
      if (payl instanceof Map) {
        sub_payl = payl.get(".");
      } else {
        sub_payl = payl;
      }
      if (filter === LIST_FILTER_ALL) {
        rc.push([key, sub_payl]);
        reduce(payl);
        continue;
      }
      if (filter === LIST_FILTER_SCAN_ERRORS_ONLY) {
        if (sub_payl.error) {
          rc.push([key, sub_payl]);
        }
        reduce(payl);
        continue;
      }
      if (filter === LIST_FILTER_EXCLUDE_SCAN_ERRORS) {
        if (!sub_payl.error) {
          rc.push([key, sub_payl]);
        }
        reduce(payl);
        continue;
      }
      console.log('Warning inconsistency in function "getFileList"!');
    }
  }
  reduce(storage.dir_map); //kickoff
  return rc;
}

function get_file_by_hmac(storage_name, hmac) {

  let storage = get_storage(storage_name);
  if (!storage) {
    return [];
  }
  let files = storage.files_by_hmac.get(hmac);
  return files;
}

function get_multiples_by_hmac(storage_name) {

  let rc = [];

  let storage = get_storage(storage_name);
  if (!storage) {
    return rc;
  }
  let iter = storage.files_by_hmac.entries();
  let step;
  while ((step = iter.next()).done == false) {
    let hmac = step.value[0];
    let files = step.value[1];
    if (files.length > 1) {
      rc.push([hmac, files]);
    }
  }
  return rc;
}

function add_storage(options) {
  if (!options) {
    throw [-1, "[options] argument is undefined or null"];
  }
  let name = options.name;
  if (!name) {
    throw [-2, '[options] argument has no \"name\" property'];
  }
  name = name.toLowerCase();
  if (global_storage.has(name)) {
    let error_description = ERR_NAME_ALREADY_EXIST[1].replace('%s', name);
    let error = ERR_NO_NAME_ALREADY_EXIST[0];
    return {
      error,
      error_description,
      onDiscovered: () => {
        throw ERR_NAME_ALREADY_EXIST;
      },
      onHashing: () => {
        throw ERR_NAME_ALREADY_EXIST;
      },
      onHashed: () => {
        throw ERR_NAME_ALREADY_EXIST;
      },
      onDiscovering: (func) => {
        throw ERR_NAME_ALREADY_EXIST;
      },
    };
  }
  let base_dirs = options.baseDirs;
  assert_array_of_strings(base_dirs, "[baseDirs option property]");
  let dir_map = new Map(base_dirs.map(cur => [cur, null])),
    state = STATE_UNINITIALIZED,
    storage = {
      name,
      dir_map,
      state,
      files_by_hmac: new Map(),
      /* paritioned in 4 groups, for faster operation */
      processing_discovery: new Set(),
      processing_hmac_hashing: new Set(),
      done_hmac: new Set(),
      done_discovered: new Set()
    };
  global_storage.set(name, storage);

  function discovered(func) {
    assert_function(func);
    storage.done_discovered.add(func);
    //delete this.onDiscovered;
    return this;
  }

  function mac_hashed(func) {
    assert_function(func);
    storage.done_hmac.add(func);
    //delete this.onHashed;
    return this;
  }

  function discovering(func) {
    assert_function(func);
    storage.processing_discovery.add(func);
    //delete this.onDiscovering;
    return this;
  }

  function hashing(func) {
    assert_function(func);
    storage.processing_hmac_hashing.add(func);
    //delete this.onHashing;
    return this;
  }

  return {
    onDiscovered: discovered,
    onHashed: mac_hashed,
    onDiscovering: discovering,
    onHashing: hashing
  };

}

function discover_files(storage_name) {

  assert_defined_and_not_null(storage_name, "storage_name");
  let storage = global_storage.get(storage_name);

  if (storage == null) {
    return {
      errno: -1,
      err_descr: "storage [" + storage_name + "] doesnt exist"
    };
  }
  if (in_arr([STATE_DISCOVERING, STATE_HASHING], storage.state)) {
    return {
      errno: -2,
      err_descr: "storage [" + storage.name + "] is already active: [" + storage.state + "]"
    };
  }
  //--all ok
  storage.state = STATE_DISCOVERING;
  //
  //--bootstrap base dirs to the count todo
  //
  const dir_map = storage.dir_map;
  storage.file_count_to_do = storage.dir_map.size;
  storage.file_count_done = 0;
  dir_map.storage = storage;
  dir_map.forEach((val, key, m) => {
    scan_dirs(m, key);
  });
  return true; //"kick off" was successfull
}

function scan_dirs(map, file_path) {
  // console.log("map,path,flags,mode", map, file_path, flags, mode);
  promiseWrap(fs.lstat, file_path).then(
    (stat) => {
      if (stat.isDirectory()) {
        //console.log(stat);
        console.log("isDirectory:".green, true);
        var map_children = new Map();
        map.set(file_path, map_children);
        map_children.set(".", stat);
        map_children.parent = map;
        map_children.storage = map.storage;
        promiseWrap(fs.readdir, file_path).then(
          (files) => {
            map.storage.file_count_to_do += files.length;
            file_processing(map.storage);
            files.forEach((file, idx, arr) => {
              scan_dirs(map_children, path.join(file_path, file));
            });
            is_file_processing_done(map.storage);
          }
        ).catch((err) => { //error in fs?readdir
          Object.assign(stat, {
            error: err
          });
          map_children.set(".", stat);
          file_processing(map.storage);
          is_file_processing_done(map.storage);
        });
      } else {
        map.set(file_path, stat);
        file_processing(map.storage);
        is_file_processing_done(map.storage);
      }
    }
  ).catch((err) => {
    map.set(file_path, {
      error: err
    });
    file_processing(map.storage);
    is_file_processing_done(map.storage);
  });
}

/** hashing */
/** hashing */
/** hashing */

function hash_files(storage_name, count_concurrent) {

  if (count_concurrent == undefined) {
    count_concurrent = 4;
  }

  assert_defined_and_not_null(storage_name, "storage_name");
  let storage = global_storage.get(storage_name);

  if (storage == null) {
    return {
      errno: -1,
      err_descr: "storage [" + storage_name + "] doesnt exist"
    };
  }
  if (!in_arr([STATE_DISCOVERED, STATE_HASHED], storage.state)) {
    return {
      errno: -2,
      err_descr: "storage [" + storage.name + "] is already active: [" + storage.state + "]"
    };
  }

  if (!g_hmac) {
    return {
      errno: -3,
      err_descr: "no hash function (md5,sha256, md4) availible on system"
    };
  }
  // --all ok
  const dir_map = storage.dir_map;
  storage.file_count_to_do = count_files(dir_map);
  storage.state = STATE_HASHING;
  //
  // --bootstrap base dirs to the count todo
  //
  storage.file_count_done = [0, 0];
  storage.files_being_processed = new Map();

  var all_files = flat_map(dir_map);
  let files_being_processed = storage.files_being_processed;

  function process_file(entry) {
    if (entry == undefined) {
      console.log('this "thread" will stop...');
      //throw new Error("wtf?");
      if (files_being_processed.size == 0) {
        console.log("FINISHED".underline.red);
        is_file_processing_done(storage);
      }
      return;
    }
    let seq = 0;
    let stat = entry[1];
    let key = entry[0];
    stat.bytes_processed = 0;
    files_being_processed.set(key, stat);
    let hmac = crypto.createHmac('sha256', SECRET);
    hmac.setEncoding('hex');
    //
    promiseWrap(fs.open, key, 'r', 0o666)
      .then((fd) => {
        let buffer = new Buffer.alloc(READ_FILE_BUF_SIZE);
        return new Promise(function (resolve, rej) {
          let signal_count = CHUNK_SIZE_100MB;

          function read_next_piece(position, buf_length = buffer.length) {
            fs.read(fd, buffer, 0, buf_length, position, (err, bytes_read, _buffer) => {
              if (err) {
                fs.close(fd);
                hmac.end();
                return rej(err);
              }
              if (bytes_read <= 0 || bytes_read == null) {
                fs.close(fd);
                hmac.end();
                return resolve(hmac.read());
              }
              hmac.update(_buffer.slice(0, bytes_read));
              stat.bytes_processed += bytes_read;
              signal_count -= bytes_read;
              if (signal_count <= 0) {
                signal_count = CHUNK_SIZE_100MB; //reset
                file_processing(Object.assign({
                  key
                }, storage));
              }
              read_next_piece(position + bytes_read);
            });
          }
          //kick off
          read_next_piece(0);
        });
      })
      .then((hmac) => {
        delete stat.error;
        stat.hmac = hmac;
        storage.file_count_done[0]++;
        storage.file_count_done[1] += stat.size || 0;
        //update set_

        let files = storage.files_by_hmac.get(hmac) || [];
        files.push(key);
        storage.files_by_hmac.set(hmac, files);

        let end_of_file = true;
        file_processing(Object.assign({
          key,
          end_of_file
        }, storage));
        //console.log(("finish:" + (++seq)).green, key, stat.hmac, "<<");
        process.nextTick(() => {
          process_file(all_files.pop());
        });
      })
      .catch((error) => {
        stat.error = error;
        delete stat.hmac;
        storage.file_count_done[0]++;
        storage.file_count_done[1] += stat.size || 0;
        let end_of_file = true;

        file_processing(
          Object.assign({
            error,
            key,
            end_of_file
          }, storage));

        process.nextTick(() => {
          process_file(all_files.pop());
        });
        console.log(("error:" + (++seq)).red, stat.bytes_processed, err);
      });
  }
  let i = 0;
  while (i < count_concurrent && all_files.length > 0) {
    process_file(all_files.pop()); //kick off
    console.log(i);
    i++;
  }
}
/*
  test
*/
var k = add_storage({
  name: "porn-stash",
  baseDirs: [
    '/home/jacobbogers/1T_seagate/testdir',
  ],
}).onDiscovered((error, result) => {
  console.log("done:", result);
  let l = get_file_list(result.name, {
    filter: LIST_FILTER_ALL
  });
  console.log('list1', l);
  hash_files("porn-stash", 3);
}).onDiscovering((error, result) => {
  console.log('ping:', result);
}).onHashing((error, result) => {
  let key = result.file_name;
  let stat = result.files_being_processed.get(key);
  let bytes_processed, size;
  if (stat) {
    if (stat.bytes_processed != undefined) {
      bytes_processed = stat.bytes_processed;
    }
    if (stat.size != undefined) {
      size = stat.size;
    }
  }
  if (stat && stat.error) {
    console.log("err:", stat.error);
  } else {
    console.log("progress: ${1}/${2} ${3} processing".replace("${1}", bytes_processed).replace("${2}", size).replace("${3}", key).green);
  }
}).onHashed((result) => {
  console.log("hashing done:", result);
  let l = get_file_list(result.name, {
    filter: LIST_FILTER_ALL
  });
  console.log(l);
  let files = get_multiples_by_hmac(result.name);
  console.log(files);
});

discover_files("porn-stash");

/**
const STATE_UNINITIALIZED = "uninitialized";
const STATE_DISCOVERING = "discovering";
const STATE_DISCOVERED = "discovered";
const STATE_HASHING = "hashing";
const STATE_HASHED = "hashed";

const EVENT_DISCOVERED = STATE_DISCOVERED;
const EVENT_HASHED = STATE_HASHED;
const EVENT_FILES_PROCESSING = "processing_files";

const LIST_FILTER_EXCLUDE_SCAN_ERRORS ="exclude_errors";
const LIST_FILTER_INCLUDE_SCAN_ERRORS = "include_errors";
const LIST_FILTER_SCAN_ERRORS_ONLY ="only_errors";

*/

module.exports = {
  states: {
    STATE_UNINITIALIZED,
    STATE_DISCOVERING,
    STATE_DISCOVERED,
    STATE_HASHING,
    STATE_HASHED
  },
  filters: {
    LIST_FILTER_EXCLUDE_SCAN_ERRORS,
    LIST_FILTER_ALL,
    LIST_FILTER_SCAN_ERRORS_ONLY
  },
  addStorage: add_storage,
  getStorage: get_storage,
  discoverFiles: discover_files,
  hashFiles: hash_files,
  getFileList: get_file_list,
  getMultiples: get_multiples_by_hmac,
  getFilesByHmac: get_file_by_hmac
}

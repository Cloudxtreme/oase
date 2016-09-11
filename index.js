'use strict';

/*

  Storage
  ========

  there should be an alert log..per storage

  storage is set to "initializing"
  test if dictionary can be opened? no? --> storage is marked unusable
  read dictionary? --> invalid configfile --> storage is marked unusable

  discovery --> if base dir is unusable --> storage is marked unusable

  +storage is marked "discovering".
  +discovery finished --> merge with dictionary! --> storage is marked "discovered"
  +only hash files the accourding to dictiontary!
  storage is marked "hashing"
  save result as new dictionary
  storage is marked "hashed"
  --
  storage is ready to receive data!!

  data uplaod is

  partial.length_file_name.file_name.uuid.[md5 has of all previous fields] (io.error  -> storage is readonly)
  rename to "file_name-0n.ext" if it already existance (io.error--> mark storage as readonly)
  put the sha2 int the dictionary in memory
  mark the dictionary for flush (io.error -> mark storage as unusable and offline)
  log all crap in alert log entry. [fixed record length, round robin rotating entries]

  Middleware
  ===========
  define partial uploaded file pattern
  skip partial uploaded file from serving via url
  if client uploading to repo, check if the same partial_file_exist and timed-out

  garbage collect timed out partial uploads, look in flattened key_list "storage.files_by_key"
  file uploaded is registerd as a partial for the storage.

*/

const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const chain_job = require('./scheduler.js');
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
const STATE_INITIALIZING = "initializing";
const STATE_DISCOVERING = "discovering";
const STATE_DISCOVERED = "discovered";
const STATE_HASHING = "hashing";
const STATE_HASHED = "hashed";
const STATE_MERGING_DICTIONARY = "merging_dictionary";
const STATE_MERGED_DICTIONARY = "dictionary_merged";
const STATE_READ_ONLY = "read_only";
const STATE_UNUSABLE = "unusable";

const LIST_FILTER_EXCLUDE_SCAN_ERRORS = "exclude_errors";
const LIST_FILTER_ALL = "include_errors";
const LIST_FILTER_SCAN_ERRORS_ONLY = "only_errors";

const EVENT_DISCOVERED = STATE_DISCOVERED;
const EVENT_HASHED = STATE_HASHED;
const EVENT_FILES_PROCESSING = "processing_files";

const CHUNK_SIZE_100MB = 1024 * 1024 * 100;
const CHUNK_SIZE_UPLOAD = 100 * 1024;
const READ_FILE_BUF_SIZE = 65336 * 4; //256k

var global_storage = new Map();

var SECRET = process.env.HMAC_SECRET || "purdy";
var TRACE = process.env.TRACE_LEVEL;

// test the hmac existance

var g_hmac = (function() {
  // lets try 3 differrent hashes
  var rc;
  try {
    rc = crypto.createHmac("sha256", SECRET);
  } catch (e) {
    rc = null;
  }
  return rc;
})();

/* generic utilities */
/* generic utilities */
/* generic utilities */

function move_property(prop_names, target, source, verify) {
  if (!(prop_names instanceof Array)) {
    prop_names = [prop_names];
  }
  for (let prop of prop_names) {
    if (verify(source[prop])) {
      target[prop] = source[prop];
      delete source[prop];
    }
  }
}

function isFunction(p) {
  return (p instanceof Function);
}

function isString(s) {
  return (typeof s === "string");
}

function nano_time() {
  let hrt = process.hrtime();
  return hrt[0] * 1E9 + hrt[1];
}

function rate(curr_ts, prev_ts, metric, time_unit) {
  let span = curr_ts - prev_ts;
  if (metric == 0) {
    return 0;
  }
  if (span == 0) {
    return undefined;
  }
  return metric / span * time_unit;
}

function flat_map_sort_on_key(map) {
  let rc = flat_map(map);
  rc.sort((a, b) => {
    let k1 = a[0];
    let k2 = b[0];
    if (k1 > k2) {
      return 1;
    }
    if (k1 < k2) {
      return -1;
    }
    return 0;
  });
  return new Map(rc);
};

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
      if (entry[1].error) {
        continue;
      }
      rc.push(entry);
    }
  }
  reduce(map);
  //sort on keys
  return rc;
}


function assert_function(func, name) {
  if (!(func instanceof Function)) {
    let e = ERR_NOT_A_FUNCTION.splice(0);
    e[1] = e[1].replace("%s", name || '');
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
    e[1] = e[1].replace("%s", name);
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
    e[1] = e[1].replace("%s", name);
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

function promise_wrap() {
  var arr = Array.from(arguments);
  var func = arr[0];
  arr.splice(0, 1);
  return new Promise(function(res, rej) {
    func.call(func /* this */ , ...arr, function(err, ctx) {
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

function pop_job_and_run(storage_name) {
  //TODO:here
  /*
  storage.job_queue = [{
    func: discover_files
  }, {
    func: hash_files,
    nr: 4
  }];
  */
}


/*
NOTE: function is_resumable_io_err

-->example
{
  [Error: ENOENT: no such file or directory, stat 'X:\\delsdfsdf.txt']
  errno: -4058,
  code: 'ENOENT',
  syscall: 'stat',
  path: 'X:\\delsdfsdf.txt'
}

----
EACCES          Permission denied (POSIX.1)
EBADF           Bad file descriptor (POSIX.1)
EBADFD          File descriptor in bad state
EDQUOT          Disk quota exceeded (POSIX.1)
EEXIST          File exists (POSIX.1)
EFBIG           File too large (POSIX.1)
EIO             Input/output error (POSIX.1)
EISDIR          Is a directory (POSIX.1)
EISNAM          Is a named type file
ELOOP           Too many levels of symbolic links (POSIX.1)
EMFILE          Too many open files (POSIX.1); commonly caused by
                exceeding the RLIMIT_NOFILE resource limit described
                in getrlimit(2)
ENAMETOOLONG    Filename too long (POSIX.1)
ENOENT          No such file or directory (POSIX.1)
ENOSPC          No space left on device (POSIX.1)
ENOTDIR         Not a directory (POSIX.1)
EPERM           Operation not permitted (POSIX.1)
EUSERS          Too many users
*/

function is_resumable_io_err(err) {
  //File doest exist No such file or directory (POSIX.1)
  const resumable = [ /*'EEXIST',*/ 'ENOENT'];
  if (in_arr(resumable, err.code)) {
    return true;
  }
  return false;
}


function json_to_dir_map(json_text) {
  if (!json_text) {
    return null;
  }
  let json;
  try {
    json = JSON.parse(json_text);
  } catch (e) {
    return null;
  }
  let current_map = new Map();
  json.forEach((entry) => {
    if (entry.full_path === ".") {
      current_map.set(".", entry.stat);
      return;
    }
    if (/dir/.test(stat.file_type)) {
      let child_map = json_to_dir_map(entry.children);
      if (!child_map) {
        return;
      }
      current_map.set(entry.full_path, child_map);
      return;
    }
    current_map.set(entry.full_map, entry.stat);
  });
  return current_map;
}

function file_type(stats) {

  let rc = '';

  if (!stats) {
    return rc;
  }

  if (stats.isFile()) {
    rc += 'file ';
  }
  if (stats.isDirectory()) {
    rc += 'dir ';
  }
  if (stats.isBlockDevice()) {
    rc += 'block-dev ';
  }
  if (stats.isCharacterDevice()) {
    rc += 'char-dev ';
  }
  if (stats.isSymbolicLink()) {
    rc += 'sym-link ';
  }
  if (stats.isFIFO()) {
    rc += 'fifo ';
  }
  if (stats.isSocket()) {
    rc += 'socket ';
  }
  stats.file_type = rc.trim();
  return rc;
}


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
    if (entry[1].error) {
      continue; //skip errors
    }
    if (typeof entry[0] == "string" && entry[1]) {
      rc[0]++;
      rc[1] += entry[1].size || 0;
    }
  }
  return rc;
}

function file_processing(storage_extended) {

  let name = storage_extended.name;
  let file_count_to_do = storage_extended.file_count_to_do;
  let file_count_done = storage_extended.file_count_done;
  let set;

  switch (storage_extended.state) {
    case STATE_DISCOVERING:
      //NOTE:: in this state, here storage_extended is not enriched and dus is the same as storage
      storage_extended.file_count_done++;
      if (storage_extended.file_count_done % 10) {
        return; //skip
      }
      set = storage_extended.processing_discovery;
      set.forEach((func, dummy, s) => {
        //callback
        process.nextTick(func,
          storage_extended.error, {
            file_count_to_do,
            file_count_done,
            name
          });
      });
      break;
    case STATE_HASHING:
      //NOTE here storage_extended is exact as storage, not enriched
      set = storage_extended.processing_hmac_hashing
      let files_being_processed = storage_extended.files_being_processed;
      set.forEach((func, dummy, s) => {
        //callback
        process.nextTick(() => {
          func(storage_extended.error, {
            file_count_to_do,
            file_count_done,
            files_being_processed,
            name,
            file_name: storage_extended.key
          });
          if (storage_extended.end_of_file) {
            files_being_processed.delete(storage_extended.key);
          }
        });
      });
      break;
    default:
      return; //skip this
  }
}

function is_file_processing_done(storage, chain_ctx) {

  let file_count_to_do = storage.file_count_to_do;
  let file_count_done = storage.file_count_done;
  //
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
          func({
            file_count_to_do,
            file_count_done,
            name
          });
        });
      });
      set.clear();
      console.log("state-discovered, nextStep");
      chain_ctx && chain_ctx.nextStep && chain_ctx.nextStep();
      break;
    case STATE_HASHING:
      //NOTE :storage_extended is not enriched here
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
      //NOTE: there is already a  [ storage.files_by_hmac ] MAP (build during the hashing)
      storage.files_by_key = flat_map_sort_on_key(storage.dir_map);
      chain_ctx && chain_ctx.nextStep && chain_ctx.nextStep();
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

function get_storage_list() {
  let rc = Array.from(global_storage);
  return rc;
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
      console.log('WARNING: inconsistency in function "getFileList"!');
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
    throw [-2, '[options] argument has no \"name\" property!'];
  }
  name = name.toLowerCase();
  if (global_storage.has(name)) {
    let error_description = ERR_NAME_ALREADY_EXIST[1].replace('%s', name);
    let error = ERR_NAME_ALREADY_EXIST[0];
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

  let base_dir = options.baseDir;
  assert_string(base_dir, "[baseDir option property]");
  let dir_map = new Map([
    [base_dir, null]
  ]);

  let dictionary = options.dictionaryDir;
  assert_string(dictionary, "[dictionaryDir option property]");


  let state = STATE_UNINITIALIZED;
  let storage = {
    name,
    dir_map,
    dictionary,
    state,
    alerts: [],
    files_by_hmac: new Map(),
    /*
       paritioned in 4 groups, for faster operation
    */
    processing_discovery: new Set(),
    processing_hmac_hashing: new Set(),
    done_hmac: new Set(),
    done_discovered: new Set()
  };

  global_storage.set(name, storage);

  function discovered(func) {
    assert_function(func);
    storage.done_discovered.add(func);
    return this;
  }

  function mac_hashed(func) {
    assert_function(func);
    storage.done_hmac.add(func);
    return this;
  }

  function discovering(func) {
    assert_function(func);
    storage.processing_discovery.add(func);
    return this;
  }

  function hashing(func) {
    assert_function(func);
    storage.processing_hmac_hashing.add(func);
    //delete this.onHashing;
    return this;
  }

  //TODO merge_with_dictionary(storage);

  return {
    onDiscovered: discovered,
    onHashed: mac_hashed,
    onDiscovering: discovering,
    onHashing: hashing
  };
}

function is_storage_being_activated(state) {
  return in_arr([
    STATE_DISCOVERING,
    STATE_DISCOVERED,
    STATE_HASHING,
    STATE_HASHED,
    STATE_MERGING_DICTIONARY,
    STATE_INITIALIZING
  ], state);
}


function is_storage_openable(state) {
  return in_arr([
    STATE_UNINITIALIZED,
    STATE_UNUSABLE /* yes here we can attempt a re-open */ ,
    STATE_READ_ONLY /* yes here we can attempt a re-open */ ,
  ], state);
}

function is_storage_discoverable(state) {
  return STATE_INITIALIZING == state;
}

function is_storage_openable_ext(storage) {

  if (!is_storage_openable(storage.state)) { //error not openable
    //what kind of error, to return proper error message
    if (is_storage_being_activated(storage.state)) {
      return {
        errno: -2,
        err_descr: "ERROR:storage [" + storage.name + "] is currently being activated: [" + storage.state + "]"
      };
    }
    //already properly opened and merged
    if (in_arr([STATE_MERGED_DICTIONARY], storage.state)) {
      return {
        errno: -2,
        err_descr: "ERROR:storage [" + storage.name + "] is already open: [" + storage.state + "]"
      };
    }
    //Not supposed to be here fall through
    throw new Error("Internal Error, call Support at jkfbogers@gmail.com");
  }
  return {
    errno: 0,
    err_descr: "ok"
  }; //all ok
}

function is_storage_discoverable(storage) {
  return (storage.state == STATE_INITIALIZING);
}

function is_storage_discoverable_ext(storage) {
  if (!is_storage_discoverable(storage)) {
    //already properly opened and merged
    if (in_arr([STATE_MERGED_DICTIONARY], storage.state)) {
      return {
        errno: -2,
        err_descr: "ERROR:storage [" + storage.name + "] is already open: [" + storage.state + "]"
      };
    }
    return {
      errno: -3,
      err_descr: "ERROR:storage [" + storage.name + "] is currently is not (re-)initialized  [" + storage.state + "]"
    };
  }
  return {
    errno: 0,
    err_descr: "ok"
  }; //all ok
}



function open_storage(storage_name) {
  let chain = chain_job();
  chain.add_step({
    func: open_dictionary,
    args: {
      storage_name: storage_name
    }
  });
  chain.add_step({
    func: discover_files,
    args: {
      storage_name: storage_name
    }
  });
  chain.add_step({
    func: hash_files,
    args: {
      storage_name: storage_name,
      count_concurrent: 4
    }
  });
  chain.add_step({
    func: () => {
      console.log("CHAIN_DONE");
    },
  });
  chain.run();
  return chain;
}

function storage_doesnt_exist_err(chain_ctx) {
  let rc = {
    errno: -1,
    err_descr: "storage [" + storage_name + "] doesnt exist"
  };
  //no choice, i have to place the error in the chain if there is no storage object
  chain_ctx.slab && (
    (chain_ctx.slab.errors = chain_ctx.slab.errors || []) &&
    (chain_ctx.slab.errors.push(rc)));
  chain_ctx.cancel && chain_ctx.cancel();
  return rc;
}


function open_dictionary(chain_ctx) {

  let storage_name = chain_ctx && chain_ctx.arguments && chain_ctx.arguments.storage_name;
  console.log("open dictionary:", storage_name);
  assert_defined_and_not_null(storage_name, "storage_name");
  let storage = global_storage.get(storage_name);
  //all ok for now
  if (storage == null) {
    console.log("storage isnt registered");
    return storage_doesnt_exist_err(chain_ctx);
  }
  //
  let rc = is_storage_openable_ext(storage);
  //
  if (rc.errno) {
    console.log("storage is not openable");
    storage.alerts.push(rc);
    chain_ctx.cancel && chain_ctx.cancel();
    return rc; //abort
  }
  //clear sailing
  storage.state = STATE_INITIALIZING;
  //
  console.log("storage.state is now INITIALIZING");
  const confFile = path.join(storage.dictionary, "storage_${name}.json".replace("${name}", storage.name));
  console.log("storage.state is now INITIALIZING,", confFile);
  //
  fs.readFile(confFile, "utf8", (err, data) => {
    if (!is_resumable_io_err(err)) {
      storage.state = STATE_UNUSABLE;
      storage.alerts.push(err);
      console.log("dictionary un-usable.");
      chain_ctx.cancel && chain_ctx.cancel();
      return;
    }
    storage.dictionary_map = json_to_dir_map(data) || new Map();
    console.log("leaving open_dictionary -> nextStep");
    chain_ctx.nextStep();
  });
}

function discover_files(chain_ctx) {
  console.log('discover files');
  let storage_name = chain_ctx && chain_ctx.arguments && chain_ctx.arguments.storage_name;
  // in case chain_ctx is just a string
  storage_name = storage_name || chain_ctx;

  assert_defined_and_not_null(storage_name, "storage_name");
  let storage = global_storage.get(storage_name);
  //all ok for now
  if (storage == null) {
    console.log("no storage with than name found");
    return storage_doesnt_exist_err(chain_ctx);
  }
  //
  //this function isnt always called from open_storage function
  //rediscovery can happen without re-reading the dictionary
  let rc = is_storage_discoverable_ext(storage);
  //
  if (rc.errno) {
    console.log("storage has wrong state", rc);
    storage.alerts.push(rc);
    chain_ctx.cancel && chain_ctx.cancel();
    return rc; //abort
  }
  //all ok
  storage.state = STATE_DISCOVERING;
  //bootstrap base dirs to the count todo
  console.log('state is now discovering');
  const dir_map = storage.dir_map;
  storage.file_count_to_do = storage.dir_map.size;
  storage.file_count_done = 0;
  dir_map.storage = storage;
  dir_map.forEach((val, key, m) => {
    console.log("scan_dir:", key);
    scan_dirs(m, key, chain_ctx); //pass on chain context
  });
  return true; //"kick off" was successfull
}

function scan_dirs(map, file_path, chain_ctx) {

  promise_wrap(fs.lstat, file_path)
    .then(
      (stat) => {
        // TODO: when implementing shortname factory method, the call goes here.
        //       call shortname function (..with process.nextTick()..) (lstat,file_path,map.storage.dir_map)
        stat.full_path = file_path;
        file_type(stat); //enrich stats with file_type
        if (!stat.isDirectory() && !(map.parent)) {
          throw new Error("the storage entry-dir is not a directory");
        }
        if (stat.isDirectory()) {
          var map_children = new Map();
          map.set(file_path, map_children);
          map_children.set(".", stat);
          map_children.parent = map;
          map_children.storage = map.storage;
          promise_wrap(fs.readdir, file_path).then(
            (files) => {
              //console.log("files discovered:", files.length);
              map.storage.file_count_to_do += files.length;
              file_processing(map.storage);
              files.forEach((file, idx, arr) => {
                process.nextTick(scan_dirs, map_children, path.join(file_path, file), chain_ctx);
              });
              is_file_processing_done(map.storage, chain_ctx);
            }
          ).catch((err) => { //error in fs?readdir
            Object.assign(stat, {
              error: err
            });
            //map_children.set(".", stat);
            file_processing(map.storage);
            is_file_processing_done(map.storage, chain_ctx);
          });
        } else {
          //console.log(file_path);
          map.set(file_path, stat);
          file_processing(map.storage);
          is_file_processing_done(map.storage, chain_ctx);
        }
      }
    ).catch((err) => {
      console.log('error:', err);
      map.set(file_path, {
        error: err
      });
      file_processing(map.storage);
      is_file_processing_done(map.storage, chain_ctx);
    });
}

/** hashing */
/** hashing */
/** hashing */

function hash_files(chain_ctx) {

  console.log('hash files');
  let storage_name = chain_ctx && chain_ctx.arguments && chain_ctx.arguments.storage_name;
  storage_name = storage_name || chain_ctx;

  let count_concurrent = chain_ctx && chain_ctx.arguments && chain_ctx.arguments.count_concurrent;
  count_concurrent = count_concurrent || 4;
  //
  assert_defined_and_not_null(storage_name, "storage_name");
  let storage = global_storage.get(storage_name);
  //
  if (storage == null) {
    return storage_doesnt_exist_err(chain_ctx);
  }
  //
  if (!in_arr([STATE_DISCOVERED, STATE_HASHED], storage.state)) {
    let rc = {
      errno: -2,
      err_descr: "storage [" + storage.name + "] is already active: [" + storage.state + "]"
    };
    storage.alerts.push(rc);
    chain_ctx.cancel && chain_ctx.cancel();
    return rc;
  }
  //
  if (!g_hmac) {
    let rc = {
      errno: -3,
      err_descr: "no hash function (md5,sha256, md4) availible on system"
    };
    storage.alerts.push(rc);
    chain_ctx.cancel && chain_ctx.cancel();
    return rc;
  }
  // -- all ok
  const dir_map = storage.dir_map;
  storage.file_count_to_do = count_files(dir_map);
  storage.state = STATE_HASHING;
  //
  // -- bootstrap base dirs to the count todo
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
        console.log("HASING FINISHED");
        is_file_processing_done(storage, chain_ctx);
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
    promise_wrap(fs.open, key, 'r', 0o666)
      .then((fd) => {
        let buffer = new Buffer.alloc(READ_FILE_BUF_SIZE);
        return new Promise(function(resolve, rej) {
          let signal_count = CHUNK_SIZE_100MB;

          function read_next_piece(position, buf_length) {
            if (buf_length == undefined) {
              buf_length = buffer.length;
            }
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
        // console.log(("finish:" + (++seq)).green, key, stat.hmac, "<<");
        process.nextTick(process_file, all_files.pop());

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
        console.log(("error:" + (++seq)), stat.bytes_processed, err);
      });
  } //function process_file
  //main part
  let i = 0;
  if (all_files.length == 0){
      chain_ctx.nextStep();
      return;
  }
  while (i < count_concurrent && all_files.length > 0) {
    process_file(all_files.pop()); //kick off
    i++;
  }
} //function hash_files



/** expressjs middleware */
/** expressjs middleware */
/** expressjs middleware */

function oase_expressjs(req, resp, next) {
  //are we on one of the storage stubs??
  let rc = /^\/([^\/]+)/.exec(req.path);
  if (!rc) {
    console.log("exit waypoint-3");
    return next(); //Skip
  }
  let storage_name = rc[1];
  if (!rc) {
    console.log("exit waypoint-2");
    return next(); //skip
  }
  let storage = get_storage(storage_name);
  if (!storage) {
    console.log("exit waypoint-1");
    return next(); //not a storage
  }

  //   the  format must be
  //   ..../storage_name/key/[physical full path]
  //    or
  //   ..../storage_name/hmac/[sha256]
  //  or
  //   .../storage_name  ==> admin console for this storage_name

  let rest_path = req.path.replace(rc[0], '');

  //admin console?

  if (rest_path === "") {
    resp.set({
      'Content-Type': 'text/json',
      'X-Storage-State': storage.state
    });
    let status = {
      name: storage.name,
      state: storage.state,
      file_count_to_do: storage.file_count_to_do,
      file_count_done: storage.file_count_done,
    }; //to do , compose

    if (storage.state == STATE_HASHING &&
      storage.files_being_processed &&
      storage.files_being_processed.size > 0) {
      //
      let fbp = Array.from(storage.files_being_processed.values());
      let mapped_fbp = fbp.map((itm) => {
        return {
          size: itm.size,
          full_path: itm.full_path,
          bytes_processed: itm.bytes_processed,
        }
      });
      Object.assign(status, {
        fbp: mapped_fbp
      });
    }
    //return full file list
    if (storage.state == STATE_HASHED) {
      let list = get_file_list(storage.name, {
        filter: LIST_FILTER_ALL
      });
      Object.assign(status, {
        files: list.map((itm) => {
          let v = itm[1];
          return {
            size: v.size,
            full_path: v.full_path,
            hmac: v.hmac,
            bytes_processed: v.bytes_processed,
            history_histogram: v.histograms || {},
            type: v.file_type,
            data_mod_time: v.mtime,
            access_time: v.atime,
            meta_data_mod_time: v.ctime,
            birth_time: v.birthtime
          };
        })
      });
    }
    resp.send(status);
    return;
  }
  //request resource, but storage must be ready first, check!
  if (storage.state != STATE_HASHED) {
    resp.set({
      'Content-Type': 'text/json',
      'X-Storage-State': storage.state
    });
    resp.status(500).send({
      error: -1,
      descr: "Storage not ready, it has state:" + storage.state
    });
    return;
  }
  //
  // ok, se now we check for pattern /xxx/yyy
  //
  rc = /^\/(key|hmac)\/(.+)$/.exec(rest_path);
  if (!rc || !rc.length == 3) {
    console.log("exit waypoint0");
    return next(); // invalid format, let other middleware handle it
  }
  let search_term = rc[2];
  let stat, files, key;
  switch (rc[1]) {
    case "key":
      key = "/" + search_term;
      stat = storage.files_by_key.get(key);
      break;
    case "hmac":
      files = storage.files_by_hmac.get(search_term);
      if (files && files.length > 0) {
        key = files[0];
        stat = storage.files_by_key.get(key);
      }
      break;
    default:
      // NOTE:arriving here should never happen the regexp prevents this
      return next();
  }
  if (!stat) {
    console.log("exit waypoint2");
    return next(); //404 file not found in a valid storage
  }
  //send file to requester
  //send_file(stat, resp, func_update, func_complete, func_err); // start sending
  send_file(stat, resp, this.func_update, this.func_complete, this.func_err);
  return;
}

function send_file(stat, resp, func_update, func_complete, func_err) {

  //defaults
  func_err = func_err || () => {};
  func_complete = func_complete || () => {};
  func_update = func_update || () => {};

  let performance = {
    rates: []
  };

  stat.histograms = stat.histograms || {
    io_err: 0,
    conn_err: 0,
    success_uploads: 0,
    broken_uploads: 0
  };

  let fis = fs.createReadStream(stat.full_path, {
    autoClose: true
  });

  let total_bytes_read = 0;
  let prev_ts = nano_time();

  if (stat.size) {
    resp.set({
      "Content-Length": stat.size
    });
  }
  fis.pause();

  fis.on("data", (chunk) => {
    total_bytes_read += chunk.length;
    if (total_bytes_read > CHUNK_SIZE_UPLOAD) {
      let temp_ts = nano_time();
      performance.rates.push({
        dt: temp_ts - prev_ts
      });
      //let rate = util.rate(temp_ts, prev_ts, total_bytes_read, 1E9);
      total_bytes_read = 0;
      process.nextTick(func_update, performance, stat);
    }
  });
  fis.on("end", () => {
    resp.end(); //must call to close pipe end
    fis.close(); //redundent
  }); // call end on the response stream aswell!
  fis.on("error", (err) => {
    if (!resp.headersSent) {

      resp.set({
        'Content-Type': 'text/json',
        'X-Error': err
      });
      resp.status(500).send({
        error: "io-error, administrator has been notified"
      });
    }
    resp.err = true;
    process.nextTick(func_err, err, stat);
    resp.end();
    fis.close();
    stat.histograms.io_err++;
  });
  resp.on("close", () => {
    process.nextTick(func_err, {
      errno: -1,
      error: "socket ended prematurely"
    }, stat);
    stat.histograms.broken_uploads++;
    resp.err = true;
    resp.end();
    fis.close();
  });
  resp.on("error", (err) => {
    process.nextTick(func_err, err, stat);
    stat.histograms.conn_err++;
    resp.err = true;
    resp.end();
    fis.close();
  });
  resp.on("finish", () => {
    if (resp.err) {
      return;
    }
    process.nextTick(func_complete, performance, stat);
    stat.histograms.success_uploads++;
  }); //all finalized
  fis.pipe(resp, {
    end: false
  });
  fis.resume();
}


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
  openStorage: open_storage,
  addStorage: add_storage,
  getStorage: get_storage,
  getStorageList: get_storage_list,
  discoverFiles: discover_files,
  hashFiles: hash_files,
  getFileList: get_file_list,
  getMultiples: get_multiples_by_hmac,
  getFilesByHmac: get_file_by_hmac,
  //confOaseExpressJS: configure_oase_expressjs //middleware
}

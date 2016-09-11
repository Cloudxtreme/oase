'use strict';

const ERR_ARGUMENT_NOT_DEFINED = [1000, "Argument %s is not defined."];
const ERR_ARGUMENT_IS_NULL = [1100, "Argument %s is NULL"];
const ERR_NOT_A_STRING = [2000, "Argument %s is not a string."]
const ERR_NOT_A_FUNCTION = [3000, "Argument %s is not a function."];
const ERR_NOT_AN_ARRAY = [3100, "Argument %s is not an array."];
const ERR_NOT_A_STR_ARRAY = [3100, "Argument %s is not an array of strings."];

module.exports = {
  move_property,
  isFunction,
  isString,
  assert_function,
  assert_array,
  assert_array_of_strings,
  assert_defined_and_not_null,
  in_arr
};

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

function assert_function(func, name) {
  if (!(func instanceof Function)) {
    let e = ERR_NOT_A_FUNCTION.splice(0);
    e[1] = e[1].replace("%s", name);
    throw e;
  }
}

function assert_array(arr, name) {
  //console.log("arr,name", arr, name);
  if (!(arr instanceof Array)) {
    let e = ERR_NOT_AN_ARRAY.splice(0);
    e[1] = e[1].replace("%s", name);
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
    e[1] = e[1].replace("%s", name);
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

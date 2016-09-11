'use strict';

const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const validator = require('./validator.js');

const move_property = validator.move_property;
const isFunction = validator.isFunction;
const isString = validator.isString;
const assert_function = validator.assert_function;
const assert_array = validator.assert_array;
const assert_array_of_strings = validator.assert_array_of_strings;
const assert_defined_and_not_null = validator.assert_defined_and_not_null;
const in_arr = validator.in_arr;

const CHAIN_STATE_ENDED = "ended";
const CHAIN_STATE_RUNNING = "running";
const CHAIN_STATE_INIT = "init";
const CHAIN_STATE_ABORTED = "aborted";

module.exports = create_chain;

function create_chain() {

  let steps = []; // steps of the job chain
  let cursor = 0;
  let chain_state = {
    state: CHAIN_STATE_INIT,
    slab: {} // this is the scratchpad , job steps can use to exchange data bewteen job steps
  };

  function active_steps() {
    let act = steps.filter((step) => {
      return (step.run_count > 0);
    });
    return act;
  }

  function run_nextstep() {

    if ([CHAIN_STATE_ENDED, CHAIN_STATE_ABORTED].indexOf(chain_state.state) >= 0) {
      return false;
    }
    chain_state.state = CHAIN_STATE_RUNNING;
    if (cursor >= steps.length) {
      if (active_steps().length == 0) {
        chain_state.state = CHAIN_STATE_ENDED;
      }
      return false;
    }
    let step = steps[cursor];
    cursor++;
    execute_step(step);
    return true;
  }

  function execute_step(step) {
    let func = step.func;
    let args = step.args;
    step.run_count++;
    func({
      nextStep: () => {
        step.run_count = Math.max(0, step.run_count - 1);
        process.nextTick(run_nextstep);
      },
      cancel: () => {
        chain_state.state = CHAIN_STATE_ABORTED;
      },
      slab: chain_state.slab,
      arguments: args
    });
  }

  return {
    add_step: (step) => {
      assert_defined_and_not_null(step, "[step]");
      step.run_count = 0;
      steps.push(step);
    },
    run: () => {
      if (steps.length == 0) {
        throw new Error("No steps for this Chain!");
      }
      console.log("RUN STATE:", chain_state.state);
      switch (chain_state.state) {
        case CHAIN_STATE_RUNNING:
          console.log("run function exit, jobs are already running");
          return false;
        case CHAIN_STATE_ENDED:
        case CHAIN_STATE_ABORTED:
          if (active_steps().length) {
            console.log("steps still running cannot restart");
            return false;
          }
        default:
          break;
      }
      chain_state.state = CHAIN_STATE_INIT;
      run_nextstep();
      return true;
    },
    stop: () => {
      if (chain_state.state = CHAIN_STATE_RUNNING) {
        chain_state.state = CHAIN_STATE_ABORTED;
        console.log('chain state is set to aborted');
        return true;
      }
      return false;
    },
  };
}

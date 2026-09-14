/******/ (() => { // webpackBootstrap
/******/ 	var __webpack_modules__ = ({

/***/ "./node_modules/dijkstrajs/dijkstra.js"
/*!*********************************************!*\
  !*** ./node_modules/dijkstrajs/dijkstra.js ***!
  \*********************************************/
(module) {

"use strict";


/******************************************************************************
 * Created 2008-08-19.
 *
 * Dijkstra path-finding functions. Adapted from the Dijkstar Python project.
 *
 * Copyright (C) 2008
 *   Wyatt Baldwin <self@wyattbaldwin.com>
 *   All rights reserved
 *
 * Licensed under the MIT license.
 *
 *   http://www.opensource.org/licenses/mit-license.php
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 *****************************************************************************/
var dijkstra = {
  single_source_shortest_paths: function (graph, s, d) {
    // Predecessor map for each node that has been encountered.
    // node ID => predecessor node ID
    var predecessors = {};

    // Costs of shortest paths from s to all nodes encountered.
    // node ID => cost
    var costs = {};
    costs[s] = 0;

    // Costs of shortest paths from s to all nodes encountered; differs from
    // `costs` in that it provides easy access to the node that currently has
    // the known shortest path from s.
    // XXX: Do we actually need both `costs` and `open`?
    var open = dijkstra.PriorityQueue.make();
    open.push(s, 0);
    var closest, u, v, cost_of_s_to_u, adjacent_nodes, cost_of_e, cost_of_s_to_u_plus_cost_of_e, cost_of_s_to_v, first_visit;
    while (!open.empty()) {
      // In the nodes remaining in graph that have a known cost from s,
      // find the node, u, that currently has the shortest path from s.
      closest = open.pop();
      u = closest.value;
      cost_of_s_to_u = closest.cost;

      // Get nodes adjacent to u...
      adjacent_nodes = graph[u] || {};

      // ...and explore the edges that connect u to those nodes, updating
      // the cost of the shortest paths to any or all of those nodes as
      // necessary. v is the node across the current edge from u.
      for (v in adjacent_nodes) {
        if (adjacent_nodes.hasOwnProperty(v)) {
          // Get the cost of the edge running from u to v.
          cost_of_e = adjacent_nodes[v];

          // Cost of s to u plus the cost of u to v across e--this is *a*
          // cost from s to v that may or may not be less than the current
          // known cost to v.
          cost_of_s_to_u_plus_cost_of_e = cost_of_s_to_u + cost_of_e;

          // If we haven't visited v yet OR if the current known cost from s to
          // v is greater than the new cost we just found (cost of s to u plus
          // cost of u to v across e), update v's cost in the cost list and
          // update v's predecessor in the predecessor list (it's now u).
          cost_of_s_to_v = costs[v];
          first_visit = typeof costs[v] === 'undefined';
          if (first_visit || cost_of_s_to_v > cost_of_s_to_u_plus_cost_of_e) {
            costs[v] = cost_of_s_to_u_plus_cost_of_e;
            open.push(v, cost_of_s_to_u_plus_cost_of_e);
            predecessors[v] = u;
          }
        }
      }
    }
    if (typeof d !== 'undefined' && typeof costs[d] === 'undefined') {
      var msg = ['Could not find a path from ', s, ' to ', d, '.'].join('');
      throw new Error(msg);
    }
    return predecessors;
  },
  extract_shortest_path_from_predecessor_list: function (predecessors, d) {
    var nodes = [];
    var u = d;
    var predecessor;
    while (u) {
      nodes.push(u);
      predecessor = predecessors[u];
      u = predecessors[u];
    }
    nodes.reverse();
    return nodes;
  },
  find_path: function (graph, s, d) {
    var predecessors = dijkstra.single_source_shortest_paths(graph, s, d);
    return dijkstra.extract_shortest_path_from_predecessor_list(predecessors, d);
  },
  /**
   * A very naive priority queue implementation.
   */
  PriorityQueue: {
    make: function (opts) {
      var T = dijkstra.PriorityQueue,
        t = {},
        key;
      opts = opts || {};
      for (key in T) {
        if (T.hasOwnProperty(key)) {
          t[key] = T[key];
        }
      }
      t.queue = [];
      t.sorter = opts.sorter || T.default_sorter;
      return t;
    },
    default_sorter: function (a, b) {
      return a.cost - b.cost;
    },
    /**
     * Add a new item to the queue and ensure the highest priority element
     * is at the front of the queue.
     */
    push: function (value, cost) {
      var item = {
        value: value,
        cost: cost
      };
      this.queue.push(item);
      this.queue.sort(this.sorter);
    },
    /**
     * Return the highest priority element in the queue.
     */
    pop: function () {
      return this.queue.shift();
    },
    empty: function () {
      return this.queue.length === 0;
    }
  }
};

// node.js module exports
if (true) {
  module.exports = dijkstra;
}

/***/ },

/***/ "./node_modules/encode-utf8/index.js"
/*!*******************************************!*\
  !*** ./node_modules/encode-utf8/index.js ***!
  \*******************************************/
(module) {

"use strict";


module.exports = function encodeUtf8(input) {
  var result = [];
  var size = input.length;
  for (var index = 0; index < size; index++) {
    var point = input.charCodeAt(index);
    if (point >= 0xD800 && point <= 0xDBFF && size > index + 1) {
      var second = input.charCodeAt(index + 1);
      if (second >= 0xDC00 && second <= 0xDFFF) {
        // https://mathiasbynens.be/notes/javascript-encoding#surrogate-formulae
        point = (point - 0xD800) * 0x400 + second - 0xDC00 + 0x10000;
        index += 1;
      }
    }

    // US-ASCII
    if (point < 0x80) {
      result.push(point);
      continue;
    }

    // 2-byte UTF-8
    if (point < 0x800) {
      result.push(point >> 6 | 192);
      result.push(point & 63 | 128);
      continue;
    }

    // 3-byte UTF-8
    if (point < 0xD800 || point >= 0xE000 && point < 0x10000) {
      result.push(point >> 12 | 224);
      result.push(point >> 6 & 63 | 128);
      result.push(point & 63 | 128);
      continue;
    }

    // 4-byte UTF-8
    if (point >= 0x10000 && point <= 0x10FFFF) {
      result.push(point >> 18 | 240);
      result.push(point >> 12 & 63 | 128);
      result.push(point >> 6 & 63 | 128);
      result.push(point & 63 | 128);
      continue;
    }

    // Invalid character
    result.push(0xEF, 0xBF, 0xBD);
  }
  return new Uint8Array(result).buffer;
};

/***/ },

/***/ "./node_modules/qrcode/lib/browser.js"
/*!********************************************!*\
  !*** ./node_modules/qrcode/lib/browser.js ***!
  \********************************************/
(__unused_webpack_module, exports, __webpack_require__) {

const canPromise = __webpack_require__(/*! ./can-promise */ "./node_modules/qrcode/lib/can-promise.js");
const QRCode = __webpack_require__(/*! ./core/qrcode */ "./node_modules/qrcode/lib/core/qrcode.js");
const CanvasRenderer = __webpack_require__(/*! ./renderer/canvas */ "./node_modules/qrcode/lib/renderer/canvas.js");
const SvgRenderer = __webpack_require__(/*! ./renderer/svg-tag.js */ "./node_modules/qrcode/lib/renderer/svg-tag.js");
function renderCanvas(renderFunc, canvas, text, opts, cb) {
  const args = [].slice.call(arguments, 1);
  const argsNum = args.length;
  const isLastArgCb = typeof args[argsNum - 1] === 'function';
  if (!isLastArgCb && !canPromise()) {
    throw new Error('Callback required as last argument');
  }
  if (isLastArgCb) {
    if (argsNum < 2) {
      throw new Error('Too few arguments provided');
    }
    if (argsNum === 2) {
      cb = text;
      text = canvas;
      canvas = opts = undefined;
    } else if (argsNum === 3) {
      if (canvas.getContext && typeof cb === 'undefined') {
        cb = opts;
        opts = undefined;
      } else {
        cb = opts;
        opts = text;
        text = canvas;
        canvas = undefined;
      }
    }
  } else {
    if (argsNum < 1) {
      throw new Error('Too few arguments provided');
    }
    if (argsNum === 1) {
      text = canvas;
      canvas = opts = undefined;
    } else if (argsNum === 2 && !canvas.getContext) {
      opts = text;
      text = canvas;
      canvas = undefined;
    }
    return new Promise(function (resolve, reject) {
      try {
        const data = QRCode.create(text, opts);
        resolve(renderFunc(data, canvas, opts));
      } catch (e) {
        reject(e);
      }
    });
  }
  try {
    const data = QRCode.create(text, opts);
    cb(null, renderFunc(data, canvas, opts));
  } catch (e) {
    cb(e);
  }
}
exports.create = QRCode.create;
exports.toCanvas = renderCanvas.bind(null, CanvasRenderer.render);
exports.toDataURL = renderCanvas.bind(null, CanvasRenderer.renderToDataURL);

// only svg for now.
exports.toString = renderCanvas.bind(null, function (data, _, opts) {
  return SvgRenderer.render(data, opts);
});

/***/ },

/***/ "./node_modules/qrcode/lib/can-promise.js"
/*!************************************************!*\
  !*** ./node_modules/qrcode/lib/can-promise.js ***!
  \************************************************/
(module) {

// can-promise has a crash in some versions of react native that dont have
// standard global objects
// https://github.com/soldair/node-qrcode/issues/157

module.exports = function () {
  return typeof Promise === 'function' && Promise.prototype && Promise.prototype.then;
};

/***/ },

/***/ "./node_modules/qrcode/lib/core/alignment-pattern.js"
/*!***********************************************************!*\
  !*** ./node_modules/qrcode/lib/core/alignment-pattern.js ***!
  \***********************************************************/
(__unused_webpack_module, exports, __webpack_require__) {

/**
 * Alignment pattern are fixed reference pattern in defined positions
 * in a matrix symbology, which enables the decode software to re-synchronise
 * the coordinate mapping of the image modules in the event of moderate amounts
 * of distortion of the image.
 *
 * Alignment patterns are present only in QR Code symbols of version 2 or larger
 * and their number depends on the symbol version.
 */

const getSymbolSize = (__webpack_require__(/*! ./utils */ "./node_modules/qrcode/lib/core/utils.js").getSymbolSize);

/**
 * Calculate the row/column coordinates of the center module of each alignment pattern
 * for the specified QR Code version.
 *
 * The alignment patterns are positioned symmetrically on either side of the diagonal
 * running from the top left corner of the symbol to the bottom right corner.
 *
 * Since positions are simmetrical only half of the coordinates are returned.
 * Each item of the array will represent in turn the x and y coordinate.
 * @see {@link getPositions}
 *
 * @param  {Number} version QR Code version
 * @return {Array}          Array of coordinate
 */
exports.getRowColCoords = function getRowColCoords(version) {
  if (version === 1) return [];
  const posCount = Math.floor(version / 7) + 2;
  const size = getSymbolSize(version);
  const intervals = size === 145 ? 26 : Math.ceil((size - 13) / (2 * posCount - 2)) * 2;
  const positions = [size - 7]; // Last coord is always (size - 7)

  for (let i = 1; i < posCount - 1; i++) {
    positions[i] = positions[i - 1] - intervals;
  }
  positions.push(6); // First coord is always 6

  return positions.reverse();
};

/**
 * Returns an array containing the positions of each alignment pattern.
 * Each array's element represent the center point of the pattern as (x, y) coordinates
 *
 * Coordinates are calculated expanding the row/column coordinates returned by {@link getRowColCoords}
 * and filtering out the items that overlaps with finder pattern
 *
 * @example
 * For a Version 7 symbol {@link getRowColCoords} returns values 6, 22 and 38.
 * The alignment patterns, therefore, are to be centered on (row, column)
 * positions (6,22), (22,6), (22,22), (22,38), (38,22), (38,38).
 * Note that the coordinates (6,6), (6,38), (38,6) are occupied by finder patterns
 * and are not therefore used for alignment patterns.
 *
 * let pos = getPositions(7)
 * // [[6,22], [22,6], [22,22], [22,38], [38,22], [38,38]]
 *
 * @param  {Number} version QR Code version
 * @return {Array}          Array of coordinates
 */
exports.getPositions = function getPositions(version) {
  const coords = [];
  const pos = exports.getRowColCoords(version);
  const posLength = pos.length;
  for (let i = 0; i < posLength; i++) {
    for (let j = 0; j < posLength; j++) {
      // Skip if position is occupied by finder patterns
      if (i === 0 && j === 0 ||
      // top-left
      i === 0 && j === posLength - 1 ||
      // bottom-left
      i === posLength - 1 && j === 0) {
        // top-right
        continue;
      }
      coords.push([pos[i], pos[j]]);
    }
  }
  return coords;
};

/***/ },

/***/ "./node_modules/qrcode/lib/core/alphanumeric-data.js"
/*!***********************************************************!*\
  !*** ./node_modules/qrcode/lib/core/alphanumeric-data.js ***!
  \***********************************************************/
(module, __unused_webpack_exports, __webpack_require__) {

const Mode = __webpack_require__(/*! ./mode */ "./node_modules/qrcode/lib/core/mode.js");

/**
 * Array of characters available in alphanumeric mode
 *
 * As per QR Code specification, to each character
 * is assigned a value from 0 to 44 which in this case coincides
 * with the array index
 *
 * @type {Array}
 */
const ALPHA_NUM_CHARS = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', ' ', '$', '%', '*', '+', '-', '.', '/', ':'];
function AlphanumericData(data) {
  this.mode = Mode.ALPHANUMERIC;
  this.data = data;
}
AlphanumericData.getBitsLength = function getBitsLength(length) {
  return 11 * Math.floor(length / 2) + 6 * (length % 2);
};
AlphanumericData.prototype.getLength = function getLength() {
  return this.data.length;
};
AlphanumericData.prototype.getBitsLength = function getBitsLength() {
  return AlphanumericData.getBitsLength(this.data.length);
};
AlphanumericData.prototype.write = function write(bitBuffer) {
  let i;

  // Input data characters are divided into groups of two characters
  // and encoded as 11-bit binary codes.
  for (i = 0; i + 2 <= this.data.length; i += 2) {
    // The character value of the first character is multiplied by 45
    let value = ALPHA_NUM_CHARS.indexOf(this.data[i]) * 45;

    // The character value of the second digit is added to the product
    value += ALPHA_NUM_CHARS.indexOf(this.data[i + 1]);

    // The sum is then stored as 11-bit binary number
    bitBuffer.put(value, 11);
  }

  // If the number of input data characters is not a multiple of two,
  // the character value of the final character is encoded as a 6-bit binary number.
  if (this.data.length % 2) {
    bitBuffer.put(ALPHA_NUM_CHARS.indexOf(this.data[i]), 6);
  }
};
module.exports = AlphanumericData;

/***/ },

/***/ "./node_modules/qrcode/lib/core/bit-buffer.js"
/*!****************************************************!*\
  !*** ./node_modules/qrcode/lib/core/bit-buffer.js ***!
  \****************************************************/
(module) {

function BitBuffer() {
  this.buffer = [];
  this.length = 0;
}
BitBuffer.prototype = {
  get: function (index) {
    const bufIndex = Math.floor(index / 8);
    return (this.buffer[bufIndex] >>> 7 - index % 8 & 1) === 1;
  },
  put: function (num, length) {
    for (let i = 0; i < length; i++) {
      this.putBit((num >>> length - i - 1 & 1) === 1);
    }
  },
  getLengthInBits: function () {
    return this.length;
  },
  putBit: function (bit) {
    const bufIndex = Math.floor(this.length / 8);
    if (this.buffer.length <= bufIndex) {
      this.buffer.push(0);
    }
    if (bit) {
      this.buffer[bufIndex] |= 0x80 >>> this.length % 8;
    }
    this.length++;
  }
};
module.exports = BitBuffer;

/***/ },

/***/ "./node_modules/qrcode/lib/core/bit-matrix.js"
/*!****************************************************!*\
  !*** ./node_modules/qrcode/lib/core/bit-matrix.js ***!
  \****************************************************/
(module) {

/**
 * Helper class to handle QR Code symbol modules
 *
 * @param {Number} size Symbol size
 */
function BitMatrix(size) {
  if (!size || size < 1) {
    throw new Error('BitMatrix size must be defined and greater than 0');
  }
  this.size = size;
  this.data = new Uint8Array(size * size);
  this.reservedBit = new Uint8Array(size * size);
}

/**
 * Set bit value at specified location
 * If reserved flag is set, this bit will be ignored during masking process
 *
 * @param {Number}  row
 * @param {Number}  col
 * @param {Boolean} value
 * @param {Boolean} reserved
 */
BitMatrix.prototype.set = function (row, col, value, reserved) {
  const index = row * this.size + col;
  this.data[index] = value;
  if (reserved) this.reservedBit[index] = true;
};

/**
 * Returns bit value at specified location
 *
 * @param  {Number}  row
 * @param  {Number}  col
 * @return {Boolean}
 */
BitMatrix.prototype.get = function (row, col) {
  return this.data[row * this.size + col];
};

/**
 * Applies xor operator at specified location
 * (used during masking process)
 *
 * @param {Number}  row
 * @param {Number}  col
 * @param {Boolean} value
 */
BitMatrix.prototype.xor = function (row, col, value) {
  this.data[row * this.size + col] ^= value;
};

/**
 * Check if bit at specified location is reserved
 *
 * @param {Number}   row
 * @param {Number}   col
 * @return {Boolean}
 */
BitMatrix.prototype.isReserved = function (row, col) {
  return this.reservedBit[row * this.size + col];
};
module.exports = BitMatrix;

/***/ },

/***/ "./node_modules/qrcode/lib/core/byte-data.js"
/*!***************************************************!*\
  !*** ./node_modules/qrcode/lib/core/byte-data.js ***!
  \***************************************************/
(module, __unused_webpack_exports, __webpack_require__) {

const encodeUtf8 = __webpack_require__(/*! encode-utf8 */ "./node_modules/encode-utf8/index.js");
const Mode = __webpack_require__(/*! ./mode */ "./node_modules/qrcode/lib/core/mode.js");
function ByteData(data) {
  this.mode = Mode.BYTE;
  if (typeof data === 'string') {
    data = encodeUtf8(data);
  }
  this.data = new Uint8Array(data);
}
ByteData.getBitsLength = function getBitsLength(length) {
  return length * 8;
};
ByteData.prototype.getLength = function getLength() {
  return this.data.length;
};
ByteData.prototype.getBitsLength = function getBitsLength() {
  return ByteData.getBitsLength(this.data.length);
};
ByteData.prototype.write = function (bitBuffer) {
  for (let i = 0, l = this.data.length; i < l; i++) {
    bitBuffer.put(this.data[i], 8);
  }
};
module.exports = ByteData;

/***/ },

/***/ "./node_modules/qrcode/lib/core/error-correction-code.js"
/*!***************************************************************!*\
  !*** ./node_modules/qrcode/lib/core/error-correction-code.js ***!
  \***************************************************************/
(__unused_webpack_module, exports, __webpack_require__) {

const ECLevel = __webpack_require__(/*! ./error-correction-level */ "./node_modules/qrcode/lib/core/error-correction-level.js");
const EC_BLOCKS_TABLE = [
// L  M  Q  H
1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 2, 2, 1, 2, 2, 4, 1, 2, 4, 4, 2, 4, 4, 4, 2, 4, 6, 5, 2, 4, 6, 6, 2, 5, 8, 8, 4, 5, 8, 8, 4, 5, 8, 11, 4, 8, 10, 11, 4, 9, 12, 16, 4, 9, 16, 16, 6, 10, 12, 18, 6, 10, 17, 16, 6, 11, 16, 19, 6, 13, 18, 21, 7, 14, 21, 25, 8, 16, 20, 25, 8, 17, 23, 25, 9, 17, 23, 34, 9, 18, 25, 30, 10, 20, 27, 32, 12, 21, 29, 35, 12, 23, 34, 37, 12, 25, 34, 40, 13, 26, 35, 42, 14, 28, 38, 45, 15, 29, 40, 48, 16, 31, 43, 51, 17, 33, 45, 54, 18, 35, 48, 57, 19, 37, 51, 60, 19, 38, 53, 63, 20, 40, 56, 66, 21, 43, 59, 70, 22, 45, 62, 74, 24, 47, 65, 77, 25, 49, 68, 81];
const EC_CODEWORDS_TABLE = [
// L  M  Q  H
7, 10, 13, 17, 10, 16, 22, 28, 15, 26, 36, 44, 20, 36, 52, 64, 26, 48, 72, 88, 36, 64, 96, 112, 40, 72, 108, 130, 48, 88, 132, 156, 60, 110, 160, 192, 72, 130, 192, 224, 80, 150, 224, 264, 96, 176, 260, 308, 104, 198, 288, 352, 120, 216, 320, 384, 132, 240, 360, 432, 144, 280, 408, 480, 168, 308, 448, 532, 180, 338, 504, 588, 196, 364, 546, 650, 224, 416, 600, 700, 224, 442, 644, 750, 252, 476, 690, 816, 270, 504, 750, 900, 300, 560, 810, 960, 312, 588, 870, 1050, 336, 644, 952, 1110, 360, 700, 1020, 1200, 390, 728, 1050, 1260, 420, 784, 1140, 1350, 450, 812, 1200, 1440, 480, 868, 1290, 1530, 510, 924, 1350, 1620, 540, 980, 1440, 1710, 570, 1036, 1530, 1800, 570, 1064, 1590, 1890, 600, 1120, 1680, 1980, 630, 1204, 1770, 2100, 660, 1260, 1860, 2220, 720, 1316, 1950, 2310, 750, 1372, 2040, 2430];

/**
 * Returns the number of error correction block that the QR Code should contain
 * for the specified version and error correction level.
 *
 * @param  {Number} version              QR Code version
 * @param  {Number} errorCorrectionLevel Error correction level
 * @return {Number}                      Number of error correction blocks
 */
exports.getBlocksCount = function getBlocksCount(version, errorCorrectionLevel) {
  switch (errorCorrectionLevel) {
    case ECLevel.L:
      return EC_BLOCKS_TABLE[(version - 1) * 4 + 0];
    case ECLevel.M:
      return EC_BLOCKS_TABLE[(version - 1) * 4 + 1];
    case ECLevel.Q:
      return EC_BLOCKS_TABLE[(version - 1) * 4 + 2];
    case ECLevel.H:
      return EC_BLOCKS_TABLE[(version - 1) * 4 + 3];
    default:
      return undefined;
  }
};

/**
 * Returns the number of error correction codewords to use for the specified
 * version and error correction level.
 *
 * @param  {Number} version              QR Code version
 * @param  {Number} errorCorrectionLevel Error correction level
 * @return {Number}                      Number of error correction codewords
 */
exports.getTotalCodewordsCount = function getTotalCodewordsCount(version, errorCorrectionLevel) {
  switch (errorCorrectionLevel) {
    case ECLevel.L:
      return EC_CODEWORDS_TABLE[(version - 1) * 4 + 0];
    case ECLevel.M:
      return EC_CODEWORDS_TABLE[(version - 1) * 4 + 1];
    case ECLevel.Q:
      return EC_CODEWORDS_TABLE[(version - 1) * 4 + 2];
    case ECLevel.H:
      return EC_CODEWORDS_TABLE[(version - 1) * 4 + 3];
    default:
      return undefined;
  }
};

/***/ },

/***/ "./node_modules/qrcode/lib/core/error-correction-level.js"
/*!****************************************************************!*\
  !*** ./node_modules/qrcode/lib/core/error-correction-level.js ***!
  \****************************************************************/
(__unused_webpack_module, exports) {

exports.L = {
  bit: 1
};
exports.M = {
  bit: 0
};
exports.Q = {
  bit: 3
};
exports.H = {
  bit: 2
};
function fromString(string) {
  if (typeof string !== 'string') {
    throw new Error('Param is not a string');
  }
  const lcStr = string.toLowerCase();
  switch (lcStr) {
    case 'l':
    case 'low':
      return exports.L;
    case 'm':
    case 'medium':
      return exports.M;
    case 'q':
    case 'quartile':
      return exports.Q;
    case 'h':
    case 'high':
      return exports.H;
    default:
      throw new Error('Unknown EC Level: ' + string);
  }
}
exports.isValid = function isValid(level) {
  return level && typeof level.bit !== 'undefined' && level.bit >= 0 && level.bit < 4;
};
exports.from = function from(value, defaultValue) {
  if (exports.isValid(value)) {
    return value;
  }
  try {
    return fromString(value);
  } catch (e) {
    return defaultValue;
  }
};

/***/ },

/***/ "./node_modules/qrcode/lib/core/finder-pattern.js"
/*!********************************************************!*\
  !*** ./node_modules/qrcode/lib/core/finder-pattern.js ***!
  \********************************************************/
(__unused_webpack_module, exports, __webpack_require__) {

const getSymbolSize = (__webpack_require__(/*! ./utils */ "./node_modules/qrcode/lib/core/utils.js").getSymbolSize);
const FINDER_PATTERN_SIZE = 7;

/**
 * Returns an array containing the positions of each finder pattern.
 * Each array's element represent the top-left point of the pattern as (x, y) coordinates
 *
 * @param  {Number} version QR Code version
 * @return {Array}          Array of coordinates
 */
exports.getPositions = function getPositions(version) {
  const size = getSymbolSize(version);
  return [
  // top-left
  [0, 0],
  // top-right
  [size - FINDER_PATTERN_SIZE, 0],
  // bottom-left
  [0, size - FINDER_PATTERN_SIZE]];
};

/***/ },

/***/ "./node_modules/qrcode/lib/core/format-info.js"
/*!*****************************************************!*\
  !*** ./node_modules/qrcode/lib/core/format-info.js ***!
  \*****************************************************/
(__unused_webpack_module, exports, __webpack_require__) {

const Utils = __webpack_require__(/*! ./utils */ "./node_modules/qrcode/lib/core/utils.js");
const G15 = 1 << 10 | 1 << 8 | 1 << 5 | 1 << 4 | 1 << 2 | 1 << 1 | 1 << 0;
const G15_MASK = 1 << 14 | 1 << 12 | 1 << 10 | 1 << 4 | 1 << 1;
const G15_BCH = Utils.getBCHDigit(G15);

/**
 * Returns format information with relative error correction bits
 *
 * The format information is a 15-bit sequence containing 5 data bits,
 * with 10 error correction bits calculated using the (15, 5) BCH code.
 *
 * @param  {Number} errorCorrectionLevel Error correction level
 * @param  {Number} mask                 Mask pattern
 * @return {Number}                      Encoded format information bits
 */
exports.getEncodedBits = function getEncodedBits(errorCorrectionLevel, mask) {
  const data = errorCorrectionLevel.bit << 3 | mask;
  let d = data << 10;
  while (Utils.getBCHDigit(d) - G15_BCH >= 0) {
    d ^= G15 << Utils.getBCHDigit(d) - G15_BCH;
  }

  // xor final data with mask pattern in order to ensure that
  // no combination of Error Correction Level and data mask pattern
  // will result in an all-zero data string
  return (data << 10 | d) ^ G15_MASK;
};

/***/ },

/***/ "./node_modules/qrcode/lib/core/galois-field.js"
/*!******************************************************!*\
  !*** ./node_modules/qrcode/lib/core/galois-field.js ***!
  \******************************************************/
(__unused_webpack_module, exports) {

const EXP_TABLE = new Uint8Array(512);
const LOG_TABLE = new Uint8Array(256)
/**
 * Precompute the log and anti-log tables for faster computation later
 *
 * For each possible value in the galois field 2^8, we will pre-compute
 * the logarithm and anti-logarithm (exponential) of this value
 *
 * ref {@link https://en.wikiversity.org/wiki/Reed%E2%80%93Solomon_codes_for_coders#Introduction_to_mathematical_fields}
 */;
(function initTables() {
  let x = 1;
  for (let i = 0; i < 255; i++) {
    EXP_TABLE[i] = x;
    LOG_TABLE[x] = i;
    x <<= 1; // multiply by 2

    // The QR code specification says to use byte-wise modulo 100011101 arithmetic.
    // This means that when a number is 256 or larger, it should be XORed with 0x11D.
    if (x & 0x100) {
      // similar to x >= 256, but a lot faster (because 0x100 == 256)
      x ^= 0x11D;
    }
  }

  // Optimization: double the size of the anti-log table so that we don't need to mod 255 to
  // stay inside the bounds (because we will mainly use this table for the multiplication of
  // two GF numbers, no more).
  // @see {@link mul}
  for (let i = 255; i < 512; i++) {
    EXP_TABLE[i] = EXP_TABLE[i - 255];
  }
})();

/**
 * Returns log value of n inside Galois Field
 *
 * @param  {Number} n
 * @return {Number}
 */
exports.log = function log(n) {
  if (n < 1) throw new Error('log(' + n + ')');
  return LOG_TABLE[n];
};

/**
 * Returns anti-log value of n inside Galois Field
 *
 * @param  {Number} n
 * @return {Number}
 */
exports.exp = function exp(n) {
  return EXP_TABLE[n];
};

/**
 * Multiplies two number inside Galois Field
 *
 * @param  {Number} x
 * @param  {Number} y
 * @return {Number}
 */
exports.mul = function mul(x, y) {
  if (x === 0 || y === 0) return 0;

  // should be EXP_TABLE[(LOG_TABLE[x] + LOG_TABLE[y]) % 255] if EXP_TABLE wasn't oversized
  // @see {@link initTables}
  return EXP_TABLE[LOG_TABLE[x] + LOG_TABLE[y]];
};

/***/ },

/***/ "./node_modules/qrcode/lib/core/kanji-data.js"
/*!****************************************************!*\
  !*** ./node_modules/qrcode/lib/core/kanji-data.js ***!
  \****************************************************/
(module, __unused_webpack_exports, __webpack_require__) {

const Mode = __webpack_require__(/*! ./mode */ "./node_modules/qrcode/lib/core/mode.js");
const Utils = __webpack_require__(/*! ./utils */ "./node_modules/qrcode/lib/core/utils.js");
function KanjiData(data) {
  this.mode = Mode.KANJI;
  this.data = data;
}
KanjiData.getBitsLength = function getBitsLength(length) {
  return length * 13;
};
KanjiData.prototype.getLength = function getLength() {
  return this.data.length;
};
KanjiData.prototype.getBitsLength = function getBitsLength() {
  return KanjiData.getBitsLength(this.data.length);
};
KanjiData.prototype.write = function (bitBuffer) {
  let i;

  // In the Shift JIS system, Kanji characters are represented by a two byte combination.
  // These byte values are shifted from the JIS X 0208 values.
  // JIS X 0208 gives details of the shift coded representation.
  for (i = 0; i < this.data.length; i++) {
    let value = Utils.toSJIS(this.data[i]);

    // For characters with Shift JIS values from 0x8140 to 0x9FFC:
    if (value >= 0x8140 && value <= 0x9FFC) {
      // Subtract 0x8140 from Shift JIS value
      value -= 0x8140;

      // For characters with Shift JIS values from 0xE040 to 0xEBBF
    } else if (value >= 0xE040 && value <= 0xEBBF) {
      // Subtract 0xC140 from Shift JIS value
      value -= 0xC140;
    } else {
      throw new Error('Invalid SJIS character: ' + this.data[i] + '\n' + 'Make sure your charset is UTF-8');
    }

    // Multiply most significant byte of result by 0xC0
    // and add least significant byte to product
    value = (value >>> 8 & 0xff) * 0xC0 + (value & 0xff);

    // Convert result to a 13-bit binary string
    bitBuffer.put(value, 13);
  }
};
module.exports = KanjiData;

/***/ },

/***/ "./node_modules/qrcode/lib/core/mask-pattern.js"
/*!******************************************************!*\
  !*** ./node_modules/qrcode/lib/core/mask-pattern.js ***!
  \******************************************************/
(__unused_webpack_module, exports) {

/**
 * Data mask pattern reference
 * @type {Object}
 */
exports.Patterns = {
  PATTERN000: 0,
  PATTERN001: 1,
  PATTERN010: 2,
  PATTERN011: 3,
  PATTERN100: 4,
  PATTERN101: 5,
  PATTERN110: 6,
  PATTERN111: 7
};

/**
 * Weighted penalty scores for the undesirable features
 * @type {Object}
 */
const PenaltyScores = {
  N1: 3,
  N2: 3,
  N3: 40,
  N4: 10
};

/**
 * Check if mask pattern value is valid
 *
 * @param  {Number}  mask    Mask pattern
 * @return {Boolean}         true if valid, false otherwise
 */
exports.isValid = function isValid(mask) {
  return mask != null && mask !== '' && !isNaN(mask) && mask >= 0 && mask <= 7;
};

/**
 * Returns mask pattern from a value.
 * If value is not valid, returns undefined
 *
 * @param  {Number|String} value        Mask pattern value
 * @return {Number}                     Valid mask pattern or undefined
 */
exports.from = function from(value) {
  return exports.isValid(value) ? parseInt(value, 10) : undefined;
};

/**
* Find adjacent modules in row/column with the same color
* and assign a penalty value.
*
* Points: N1 + i
* i is the amount by which the number of adjacent modules of the same color exceeds 5
*/
exports.getPenaltyN1 = function getPenaltyN1(data) {
  const size = data.size;
  let points = 0;
  let sameCountCol = 0;
  let sameCountRow = 0;
  let lastCol = null;
  let lastRow = null;
  for (let row = 0; row < size; row++) {
    sameCountCol = sameCountRow = 0;
    lastCol = lastRow = null;
    for (let col = 0; col < size; col++) {
      let module = data.get(row, col);
      if (module === lastCol) {
        sameCountCol++;
      } else {
        if (sameCountCol >= 5) points += PenaltyScores.N1 + (sameCountCol - 5);
        lastCol = module;
        sameCountCol = 1;
      }
      module = data.get(col, row);
      if (module === lastRow) {
        sameCountRow++;
      } else {
        if (sameCountRow >= 5) points += PenaltyScores.N1 + (sameCountRow - 5);
        lastRow = module;
        sameCountRow = 1;
      }
    }
    if (sameCountCol >= 5) points += PenaltyScores.N1 + (sameCountCol - 5);
    if (sameCountRow >= 5) points += PenaltyScores.N1 + (sameCountRow - 5);
  }
  return points;
};

/**
 * Find 2x2 blocks with the same color and assign a penalty value
 *
 * Points: N2 * (m - 1) * (n - 1)
 */
exports.getPenaltyN2 = function getPenaltyN2(data) {
  const size = data.size;
  let points = 0;
  for (let row = 0; row < size - 1; row++) {
    for (let col = 0; col < size - 1; col++) {
      const last = data.get(row, col) + data.get(row, col + 1) + data.get(row + 1, col) + data.get(row + 1, col + 1);
      if (last === 4 || last === 0) points++;
    }
  }
  return points * PenaltyScores.N2;
};

/**
 * Find 1:1:3:1:1 ratio (dark:light:dark:light:dark) pattern in row/column,
 * preceded or followed by light area 4 modules wide
 *
 * Points: N3 * number of pattern found
 */
exports.getPenaltyN3 = function getPenaltyN3(data) {
  const size = data.size;
  let points = 0;
  let bitsCol = 0;
  let bitsRow = 0;
  for (let row = 0; row < size; row++) {
    bitsCol = bitsRow = 0;
    for (let col = 0; col < size; col++) {
      bitsCol = bitsCol << 1 & 0x7FF | data.get(row, col);
      if (col >= 10 && (bitsCol === 0x5D0 || bitsCol === 0x05D)) points++;
      bitsRow = bitsRow << 1 & 0x7FF | data.get(col, row);
      if (col >= 10 && (bitsRow === 0x5D0 || bitsRow === 0x05D)) points++;
    }
  }
  return points * PenaltyScores.N3;
};

/**
 * Calculate proportion of dark modules in entire symbol
 *
 * Points: N4 * k
 *
 * k is the rating of the deviation of the proportion of dark modules
 * in the symbol from 50% in steps of 5%
 */
exports.getPenaltyN4 = function getPenaltyN4(data) {
  let darkCount = 0;
  const modulesCount = data.data.length;
  for (let i = 0; i < modulesCount; i++) darkCount += data.data[i];
  const k = Math.abs(Math.ceil(darkCount * 100 / modulesCount / 5) - 10);
  return k * PenaltyScores.N4;
};

/**
 * Return mask value at given position
 *
 * @param  {Number} maskPattern Pattern reference value
 * @param  {Number} i           Row
 * @param  {Number} j           Column
 * @return {Boolean}            Mask value
 */
function getMaskAt(maskPattern, i, j) {
  switch (maskPattern) {
    case exports.Patterns.PATTERN000:
      return (i + j) % 2 === 0;
    case exports.Patterns.PATTERN001:
      return i % 2 === 0;
    case exports.Patterns.PATTERN010:
      return j % 3 === 0;
    case exports.Patterns.PATTERN011:
      return (i + j) % 3 === 0;
    case exports.Patterns.PATTERN100:
      return (Math.floor(i / 2) + Math.floor(j / 3)) % 2 === 0;
    case exports.Patterns.PATTERN101:
      return i * j % 2 + i * j % 3 === 0;
    case exports.Patterns.PATTERN110:
      return (i * j % 2 + i * j % 3) % 2 === 0;
    case exports.Patterns.PATTERN111:
      return (i * j % 3 + (i + j) % 2) % 2 === 0;
    default:
      throw new Error('bad maskPattern:' + maskPattern);
  }
}

/**
 * Apply a mask pattern to a BitMatrix
 *
 * @param  {Number}    pattern Pattern reference number
 * @param  {BitMatrix} data    BitMatrix data
 */
exports.applyMask = function applyMask(pattern, data) {
  const size = data.size;
  for (let col = 0; col < size; col++) {
    for (let row = 0; row < size; row++) {
      if (data.isReserved(row, col)) continue;
      data.xor(row, col, getMaskAt(pattern, row, col));
    }
  }
};

/**
 * Returns the best mask pattern for data
 *
 * @param  {BitMatrix} data
 * @return {Number} Mask pattern reference number
 */
exports.getBestMask = function getBestMask(data, setupFormatFunc) {
  const numPatterns = Object.keys(exports.Patterns).length;
  let bestPattern = 0;
  let lowerPenalty = Infinity;
  for (let p = 0; p < numPatterns; p++) {
    setupFormatFunc(p);
    exports.applyMask(p, data);

    // Calculate penalty
    const penalty = exports.getPenaltyN1(data) + exports.getPenaltyN2(data) + exports.getPenaltyN3(data) + exports.getPenaltyN4(data);

    // Undo previously applied mask
    exports.applyMask(p, data);
    if (penalty < lowerPenalty) {
      lowerPenalty = penalty;
      bestPattern = p;
    }
  }
  return bestPattern;
};

/***/ },

/***/ "./node_modules/qrcode/lib/core/mode.js"
/*!**********************************************!*\
  !*** ./node_modules/qrcode/lib/core/mode.js ***!
  \**********************************************/
(__unused_webpack_module, exports, __webpack_require__) {

const VersionCheck = __webpack_require__(/*! ./version-check */ "./node_modules/qrcode/lib/core/version-check.js");
const Regex = __webpack_require__(/*! ./regex */ "./node_modules/qrcode/lib/core/regex.js");

/**
 * Numeric mode encodes data from the decimal digit set (0 - 9)
 * (byte values 30HEX to 39HEX).
 * Normally, 3 data characters are represented by 10 bits.
 *
 * @type {Object}
 */
exports.NUMERIC = {
  id: 'Numeric',
  bit: 1 << 0,
  ccBits: [10, 12, 14]
};

/**
 * Alphanumeric mode encodes data from a set of 45 characters,
 * i.e. 10 numeric digits (0 - 9),
 *      26 alphabetic characters (A - Z),
 *   and 9 symbols (SP, $, %, *, +, -, ., /, :).
 * Normally, two input characters are represented by 11 bits.
 *
 * @type {Object}
 */
exports.ALPHANUMERIC = {
  id: 'Alphanumeric',
  bit: 1 << 1,
  ccBits: [9, 11, 13]
};

/**
 * In byte mode, data is encoded at 8 bits per character.
 *
 * @type {Object}
 */
exports.BYTE = {
  id: 'Byte',
  bit: 1 << 2,
  ccBits: [8, 16, 16]
};

/**
 * The Kanji mode efficiently encodes Kanji characters in accordance with
 * the Shift JIS system based on JIS X 0208.
 * The Shift JIS values are shifted from the JIS X 0208 values.
 * JIS X 0208 gives details of the shift coded representation.
 * Each two-byte character value is compacted to a 13-bit binary codeword.
 *
 * @type {Object}
 */
exports.KANJI = {
  id: 'Kanji',
  bit: 1 << 3,
  ccBits: [8, 10, 12]
};

/**
 * Mixed mode will contain a sequences of data in a combination of any of
 * the modes described above
 *
 * @type {Object}
 */
exports.MIXED = {
  bit: -1
};

/**
 * Returns the number of bits needed to store the data length
 * according to QR Code specifications.
 *
 * @param  {Mode}   mode    Data mode
 * @param  {Number} version QR Code version
 * @return {Number}         Number of bits
 */
exports.getCharCountIndicator = function getCharCountIndicator(mode, version) {
  if (!mode.ccBits) throw new Error('Invalid mode: ' + mode);
  if (!VersionCheck.isValid(version)) {
    throw new Error('Invalid version: ' + version);
  }
  if (version >= 1 && version < 10) return mode.ccBits[0];else if (version < 27) return mode.ccBits[1];
  return mode.ccBits[2];
};

/**
 * Returns the most efficient mode to store the specified data
 *
 * @param  {String} dataStr Input data string
 * @return {Mode}           Best mode
 */
exports.getBestModeForData = function getBestModeForData(dataStr) {
  if (Regex.testNumeric(dataStr)) return exports.NUMERIC;else if (Regex.testAlphanumeric(dataStr)) return exports.ALPHANUMERIC;else if (Regex.testKanji(dataStr)) return exports.KANJI;else return exports.BYTE;
};

/**
 * Return mode name as string
 *
 * @param {Mode} mode Mode object
 * @returns {String}  Mode name
 */
exports.toString = function toString(mode) {
  if (mode && mode.id) return mode.id;
  throw new Error('Invalid mode');
};

/**
 * Check if input param is a valid mode object
 *
 * @param   {Mode}    mode Mode object
 * @returns {Boolean} True if valid mode, false otherwise
 */
exports.isValid = function isValid(mode) {
  return mode && mode.bit && mode.ccBits;
};

/**
 * Get mode object from its name
 *
 * @param   {String} string Mode name
 * @returns {Mode}          Mode object
 */
function fromString(string) {
  if (typeof string !== 'string') {
    throw new Error('Param is not a string');
  }
  const lcStr = string.toLowerCase();
  switch (lcStr) {
    case 'numeric':
      return exports.NUMERIC;
    case 'alphanumeric':
      return exports.ALPHANUMERIC;
    case 'kanji':
      return exports.KANJI;
    case 'byte':
      return exports.BYTE;
    default:
      throw new Error('Unknown mode: ' + string);
  }
}

/**
 * Returns mode from a value.
 * If value is not a valid mode, returns defaultValue
 *
 * @param  {Mode|String} value        Encoding mode
 * @param  {Mode}        defaultValue Fallback value
 * @return {Mode}                     Encoding mode
 */
exports.from = function from(value, defaultValue) {
  if (exports.isValid(value)) {
    return value;
  }
  try {
    return fromString(value);
  } catch (e) {
    return defaultValue;
  }
};

/***/ },

/***/ "./node_modules/qrcode/lib/core/numeric-data.js"
/*!******************************************************!*\
  !*** ./node_modules/qrcode/lib/core/numeric-data.js ***!
  \******************************************************/
(module, __unused_webpack_exports, __webpack_require__) {

const Mode = __webpack_require__(/*! ./mode */ "./node_modules/qrcode/lib/core/mode.js");
function NumericData(data) {
  this.mode = Mode.NUMERIC;
  this.data = data.toString();
}
NumericData.getBitsLength = function getBitsLength(length) {
  return 10 * Math.floor(length / 3) + (length % 3 ? length % 3 * 3 + 1 : 0);
};
NumericData.prototype.getLength = function getLength() {
  return this.data.length;
};
NumericData.prototype.getBitsLength = function getBitsLength() {
  return NumericData.getBitsLength(this.data.length);
};
NumericData.prototype.write = function write(bitBuffer) {
  let i, group, value;

  // The input data string is divided into groups of three digits,
  // and each group is converted to its 10-bit binary equivalent.
  for (i = 0; i + 3 <= this.data.length; i += 3) {
    group = this.data.substr(i, 3);
    value = parseInt(group, 10);
    bitBuffer.put(value, 10);
  }

  // If the number of input digits is not an exact multiple of three,
  // the final one or two digits are converted to 4 or 7 bits respectively.
  const remainingNum = this.data.length - i;
  if (remainingNum > 0) {
    group = this.data.substr(i);
    value = parseInt(group, 10);
    bitBuffer.put(value, remainingNum * 3 + 1);
  }
};
module.exports = NumericData;

/***/ },

/***/ "./node_modules/qrcode/lib/core/polynomial.js"
/*!****************************************************!*\
  !*** ./node_modules/qrcode/lib/core/polynomial.js ***!
  \****************************************************/
(__unused_webpack_module, exports, __webpack_require__) {

const GF = __webpack_require__(/*! ./galois-field */ "./node_modules/qrcode/lib/core/galois-field.js");

/**
 * Multiplies two polynomials inside Galois Field
 *
 * @param  {Uint8Array} p1 Polynomial
 * @param  {Uint8Array} p2 Polynomial
 * @return {Uint8Array}    Product of p1 and p2
 */
exports.mul = function mul(p1, p2) {
  const coeff = new Uint8Array(p1.length + p2.length - 1);
  for (let i = 0; i < p1.length; i++) {
    for (let j = 0; j < p2.length; j++) {
      coeff[i + j] ^= GF.mul(p1[i], p2[j]);
    }
  }
  return coeff;
};

/**
 * Calculate the remainder of polynomials division
 *
 * @param  {Uint8Array} divident Polynomial
 * @param  {Uint8Array} divisor  Polynomial
 * @return {Uint8Array}          Remainder
 */
exports.mod = function mod(divident, divisor) {
  let result = new Uint8Array(divident);
  while (result.length - divisor.length >= 0) {
    const coeff = result[0];
    for (let i = 0; i < divisor.length; i++) {
      result[i] ^= GF.mul(divisor[i], coeff);
    }

    // remove all zeros from buffer head
    let offset = 0;
    while (offset < result.length && result[offset] === 0) offset++;
    result = result.slice(offset);
  }
  return result;
};

/**
 * Generate an irreducible generator polynomial of specified degree
 * (used by Reed-Solomon encoder)
 *
 * @param  {Number} degree Degree of the generator polynomial
 * @return {Uint8Array}    Buffer containing polynomial coefficients
 */
exports.generateECPolynomial = function generateECPolynomial(degree) {
  let poly = new Uint8Array([1]);
  for (let i = 0; i < degree; i++) {
    poly = exports.mul(poly, new Uint8Array([1, GF.exp(i)]));
  }
  return poly;
};

/***/ },

/***/ "./node_modules/qrcode/lib/core/qrcode.js"
/*!************************************************!*\
  !*** ./node_modules/qrcode/lib/core/qrcode.js ***!
  \************************************************/
(__unused_webpack_module, exports, __webpack_require__) {

const Utils = __webpack_require__(/*! ./utils */ "./node_modules/qrcode/lib/core/utils.js");
const ECLevel = __webpack_require__(/*! ./error-correction-level */ "./node_modules/qrcode/lib/core/error-correction-level.js");
const BitBuffer = __webpack_require__(/*! ./bit-buffer */ "./node_modules/qrcode/lib/core/bit-buffer.js");
const BitMatrix = __webpack_require__(/*! ./bit-matrix */ "./node_modules/qrcode/lib/core/bit-matrix.js");
const AlignmentPattern = __webpack_require__(/*! ./alignment-pattern */ "./node_modules/qrcode/lib/core/alignment-pattern.js");
const FinderPattern = __webpack_require__(/*! ./finder-pattern */ "./node_modules/qrcode/lib/core/finder-pattern.js");
const MaskPattern = __webpack_require__(/*! ./mask-pattern */ "./node_modules/qrcode/lib/core/mask-pattern.js");
const ECCode = __webpack_require__(/*! ./error-correction-code */ "./node_modules/qrcode/lib/core/error-correction-code.js");
const ReedSolomonEncoder = __webpack_require__(/*! ./reed-solomon-encoder */ "./node_modules/qrcode/lib/core/reed-solomon-encoder.js");
const Version = __webpack_require__(/*! ./version */ "./node_modules/qrcode/lib/core/version.js");
const FormatInfo = __webpack_require__(/*! ./format-info */ "./node_modules/qrcode/lib/core/format-info.js");
const Mode = __webpack_require__(/*! ./mode */ "./node_modules/qrcode/lib/core/mode.js");
const Segments = __webpack_require__(/*! ./segments */ "./node_modules/qrcode/lib/core/segments.js");

/**
 * QRCode for JavaScript
 *
 * modified by Ryan Day for nodejs support
 * Copyright (c) 2011 Ryan Day
 *
 * Licensed under the MIT license:
 *   http://www.opensource.org/licenses/mit-license.php
 *
//---------------------------------------------------------------------
// QRCode for JavaScript
//
// Copyright (c) 2009 Kazuhiko Arase
//
// URL: http://www.d-project.com/
//
// Licensed under the MIT license:
//   http://www.opensource.org/licenses/mit-license.php
//
// The word "QR Code" is registered trademark of
// DENSO WAVE INCORPORATED
//   http://www.denso-wave.com/qrcode/faqpatent-e.html
//
//---------------------------------------------------------------------
*/

/**
 * Add finder patterns bits to matrix
 *
 * @param  {BitMatrix} matrix  Modules matrix
 * @param  {Number}    version QR Code version
 */
function setupFinderPattern(matrix, version) {
  const size = matrix.size;
  const pos = FinderPattern.getPositions(version);
  for (let i = 0; i < pos.length; i++) {
    const row = pos[i][0];
    const col = pos[i][1];
    for (let r = -1; r <= 7; r++) {
      if (row + r <= -1 || size <= row + r) continue;
      for (let c = -1; c <= 7; c++) {
        if (col + c <= -1 || size <= col + c) continue;
        if (r >= 0 && r <= 6 && (c === 0 || c === 6) || c >= 0 && c <= 6 && (r === 0 || r === 6) || r >= 2 && r <= 4 && c >= 2 && c <= 4) {
          matrix.set(row + r, col + c, true, true);
        } else {
          matrix.set(row + r, col + c, false, true);
        }
      }
    }
  }
}

/**
 * Add timing pattern bits to matrix
 *
 * Note: this function must be called before {@link setupAlignmentPattern}
 *
 * @param  {BitMatrix} matrix Modules matrix
 */
function setupTimingPattern(matrix) {
  const size = matrix.size;
  for (let r = 8; r < size - 8; r++) {
    const value = r % 2 === 0;
    matrix.set(r, 6, value, true);
    matrix.set(6, r, value, true);
  }
}

/**
 * Add alignment patterns bits to matrix
 *
 * Note: this function must be called after {@link setupTimingPattern}
 *
 * @param  {BitMatrix} matrix  Modules matrix
 * @param  {Number}    version QR Code version
 */
function setupAlignmentPattern(matrix, version) {
  const pos = AlignmentPattern.getPositions(version);
  for (let i = 0; i < pos.length; i++) {
    const row = pos[i][0];
    const col = pos[i][1];
    for (let r = -2; r <= 2; r++) {
      for (let c = -2; c <= 2; c++) {
        if (r === -2 || r === 2 || c === -2 || c === 2 || r === 0 && c === 0) {
          matrix.set(row + r, col + c, true, true);
        } else {
          matrix.set(row + r, col + c, false, true);
        }
      }
    }
  }
}

/**
 * Add version info bits to matrix
 *
 * @param  {BitMatrix} matrix  Modules matrix
 * @param  {Number}    version QR Code version
 */
function setupVersionInfo(matrix, version) {
  const size = matrix.size;
  const bits = Version.getEncodedBits(version);
  let row, col, mod;
  for (let i = 0; i < 18; i++) {
    row = Math.floor(i / 3);
    col = i % 3 + size - 8 - 3;
    mod = (bits >> i & 1) === 1;
    matrix.set(row, col, mod, true);
    matrix.set(col, row, mod, true);
  }
}

/**
 * Add format info bits to matrix
 *
 * @param  {BitMatrix} matrix               Modules matrix
 * @param  {ErrorCorrectionLevel}    errorCorrectionLevel Error correction level
 * @param  {Number}    maskPattern          Mask pattern reference value
 */
function setupFormatInfo(matrix, errorCorrectionLevel, maskPattern) {
  const size = matrix.size;
  const bits = FormatInfo.getEncodedBits(errorCorrectionLevel, maskPattern);
  let i, mod;
  for (i = 0; i < 15; i++) {
    mod = (bits >> i & 1) === 1;

    // vertical
    if (i < 6) {
      matrix.set(i, 8, mod, true);
    } else if (i < 8) {
      matrix.set(i + 1, 8, mod, true);
    } else {
      matrix.set(size - 15 + i, 8, mod, true);
    }

    // horizontal
    if (i < 8) {
      matrix.set(8, size - i - 1, mod, true);
    } else if (i < 9) {
      matrix.set(8, 15 - i - 1 + 1, mod, true);
    } else {
      matrix.set(8, 15 - i - 1, mod, true);
    }
  }

  // fixed module
  matrix.set(size - 8, 8, 1, true);
}

/**
 * Add encoded data bits to matrix
 *
 * @param  {BitMatrix}  matrix Modules matrix
 * @param  {Uint8Array} data   Data codewords
 */
function setupData(matrix, data) {
  const size = matrix.size;
  let inc = -1;
  let row = size - 1;
  let bitIndex = 7;
  let byteIndex = 0;
  for (let col = size - 1; col > 0; col -= 2) {
    if (col === 6) col--;
    while (true) {
      for (let c = 0; c < 2; c++) {
        if (!matrix.isReserved(row, col - c)) {
          let dark = false;
          if (byteIndex < data.length) {
            dark = (data[byteIndex] >>> bitIndex & 1) === 1;
          }
          matrix.set(row, col - c, dark);
          bitIndex--;
          if (bitIndex === -1) {
            byteIndex++;
            bitIndex = 7;
          }
        }
      }
      row += inc;
      if (row < 0 || size <= row) {
        row -= inc;
        inc = -inc;
        break;
      }
    }
  }
}

/**
 * Create encoded codewords from data input
 *
 * @param  {Number}   version              QR Code version
 * @param  {ErrorCorrectionLevel}   errorCorrectionLevel Error correction level
 * @param  {ByteData} data                 Data input
 * @return {Uint8Array}                    Buffer containing encoded codewords
 */
function createData(version, errorCorrectionLevel, segments) {
  // Prepare data buffer
  const buffer = new BitBuffer();
  segments.forEach(function (data) {
    // prefix data with mode indicator (4 bits)
    buffer.put(data.mode.bit, 4);

    // Prefix data with character count indicator.
    // The character count indicator is a string of bits that represents the
    // number of characters that are being encoded.
    // The character count indicator must be placed after the mode indicator
    // and must be a certain number of bits long, depending on the QR version
    // and data mode
    // @see {@link Mode.getCharCountIndicator}.
    buffer.put(data.getLength(), Mode.getCharCountIndicator(data.mode, version));

    // add binary data sequence to buffer
    data.write(buffer);
  });

  // Calculate required number of bits
  const totalCodewords = Utils.getSymbolTotalCodewords(version);
  const ecTotalCodewords = ECCode.getTotalCodewordsCount(version, errorCorrectionLevel);
  const dataTotalCodewordsBits = (totalCodewords - ecTotalCodewords) * 8;

  // Add a terminator.
  // If the bit string is shorter than the total number of required bits,
  // a terminator of up to four 0s must be added to the right side of the string.
  // If the bit string is more than four bits shorter than the required number of bits,
  // add four 0s to the end.
  if (buffer.getLengthInBits() + 4 <= dataTotalCodewordsBits) {
    buffer.put(0, 4);
  }

  // If the bit string is fewer than four bits shorter, add only the number of 0s that
  // are needed to reach the required number of bits.

  // After adding the terminator, if the number of bits in the string is not a multiple of 8,
  // pad the string on the right with 0s to make the string's length a multiple of 8.
  while (buffer.getLengthInBits() % 8 !== 0) {
    buffer.putBit(0);
  }

  // Add pad bytes if the string is still shorter than the total number of required bits.
  // Extend the buffer to fill the data capacity of the symbol corresponding to
  // the Version and Error Correction Level by adding the Pad Codewords 11101100 (0xEC)
  // and 00010001 (0x11) alternately.
  const remainingByte = (dataTotalCodewordsBits - buffer.getLengthInBits()) / 8;
  for (let i = 0; i < remainingByte; i++) {
    buffer.put(i % 2 ? 0x11 : 0xEC, 8);
  }
  return createCodewords(buffer, version, errorCorrectionLevel);
}

/**
 * Encode input data with Reed-Solomon and return codewords with
 * relative error correction bits
 *
 * @param  {BitBuffer} bitBuffer            Data to encode
 * @param  {Number}    version              QR Code version
 * @param  {ErrorCorrectionLevel} errorCorrectionLevel Error correction level
 * @return {Uint8Array}                     Buffer containing encoded codewords
 */
function createCodewords(bitBuffer, version, errorCorrectionLevel) {
  // Total codewords for this QR code version (Data + Error correction)
  const totalCodewords = Utils.getSymbolTotalCodewords(version);

  // Total number of error correction codewords
  const ecTotalCodewords = ECCode.getTotalCodewordsCount(version, errorCorrectionLevel);

  // Total number of data codewords
  const dataTotalCodewords = totalCodewords - ecTotalCodewords;

  // Total number of blocks
  const ecTotalBlocks = ECCode.getBlocksCount(version, errorCorrectionLevel);

  // Calculate how many blocks each group should contain
  const blocksInGroup2 = totalCodewords % ecTotalBlocks;
  const blocksInGroup1 = ecTotalBlocks - blocksInGroup2;
  const totalCodewordsInGroup1 = Math.floor(totalCodewords / ecTotalBlocks);
  const dataCodewordsInGroup1 = Math.floor(dataTotalCodewords / ecTotalBlocks);
  const dataCodewordsInGroup2 = dataCodewordsInGroup1 + 1;

  // Number of EC codewords is the same for both groups
  const ecCount = totalCodewordsInGroup1 - dataCodewordsInGroup1;

  // Initialize a Reed-Solomon encoder with a generator polynomial of degree ecCount
  const rs = new ReedSolomonEncoder(ecCount);
  let offset = 0;
  const dcData = new Array(ecTotalBlocks);
  const ecData = new Array(ecTotalBlocks);
  let maxDataSize = 0;
  const buffer = new Uint8Array(bitBuffer.buffer);

  // Divide the buffer into the required number of blocks
  for (let b = 0; b < ecTotalBlocks; b++) {
    const dataSize = b < blocksInGroup1 ? dataCodewordsInGroup1 : dataCodewordsInGroup2;

    // extract a block of data from buffer
    dcData[b] = buffer.slice(offset, offset + dataSize);

    // Calculate EC codewords for this data block
    ecData[b] = rs.encode(dcData[b]);
    offset += dataSize;
    maxDataSize = Math.max(maxDataSize, dataSize);
  }

  // Create final data
  // Interleave the data and error correction codewords from each block
  const data = new Uint8Array(totalCodewords);
  let index = 0;
  let i, r;

  // Add data codewords
  for (i = 0; i < maxDataSize; i++) {
    for (r = 0; r < ecTotalBlocks; r++) {
      if (i < dcData[r].length) {
        data[index++] = dcData[r][i];
      }
    }
  }

  // Apped EC codewords
  for (i = 0; i < ecCount; i++) {
    for (r = 0; r < ecTotalBlocks; r++) {
      data[index++] = ecData[r][i];
    }
  }
  return data;
}

/**
 * Build QR Code symbol
 *
 * @param  {String} data                 Input string
 * @param  {Number} version              QR Code version
 * @param  {ErrorCorretionLevel} errorCorrectionLevel Error level
 * @param  {MaskPattern} maskPattern     Mask pattern
 * @return {Object}                      Object containing symbol data
 */
function createSymbol(data, version, errorCorrectionLevel, maskPattern) {
  let segments;
  if (Array.isArray(data)) {
    segments = Segments.fromArray(data);
  } else if (typeof data === 'string') {
    let estimatedVersion = version;
    if (!estimatedVersion) {
      const rawSegments = Segments.rawSplit(data);

      // Estimate best version that can contain raw splitted segments
      estimatedVersion = Version.getBestVersionForData(rawSegments, errorCorrectionLevel);
    }

    // Build optimized segments
    // If estimated version is undefined, try with the highest version
    segments = Segments.fromString(data, estimatedVersion || 40);
  } else {
    throw new Error('Invalid data');
  }

  // Get the min version that can contain data
  const bestVersion = Version.getBestVersionForData(segments, errorCorrectionLevel);

  // If no version is found, data cannot be stored
  if (!bestVersion) {
    throw new Error('The amount of data is too big to be stored in a QR Code');
  }

  // If not specified, use min version as default
  if (!version) {
    version = bestVersion;

    // Check if the specified version can contain the data
  } else if (version < bestVersion) {
    throw new Error('\n' + 'The chosen QR Code version cannot contain this amount of data.\n' + 'Minimum version required to store current data is: ' + bestVersion + '.\n');
  }
  const dataBits = createData(version, errorCorrectionLevel, segments);

  // Allocate matrix buffer
  const moduleCount = Utils.getSymbolSize(version);
  const modules = new BitMatrix(moduleCount);

  // Add function modules
  setupFinderPattern(modules, version);
  setupTimingPattern(modules);
  setupAlignmentPattern(modules, version);

  // Add temporary dummy bits for format info just to set them as reserved.
  // This is needed to prevent these bits from being masked by {@link MaskPattern.applyMask}
  // since the masking operation must be performed only on the encoding region.
  // These blocks will be replaced with correct values later in code.
  setupFormatInfo(modules, errorCorrectionLevel, 0);
  if (version >= 7) {
    setupVersionInfo(modules, version);
  }

  // Add data codewords
  setupData(modules, dataBits);
  if (isNaN(maskPattern)) {
    // Find best mask pattern
    maskPattern = MaskPattern.getBestMask(modules, setupFormatInfo.bind(null, modules, errorCorrectionLevel));
  }

  // Apply mask pattern
  MaskPattern.applyMask(maskPattern, modules);

  // Replace format info bits with correct values
  setupFormatInfo(modules, errorCorrectionLevel, maskPattern);
  return {
    modules: modules,
    version: version,
    errorCorrectionLevel: errorCorrectionLevel,
    maskPattern: maskPattern,
    segments: segments
  };
}

/**
 * QR Code
 *
 * @param {String | Array} data                 Input data
 * @param {Object} options                      Optional configurations
 * @param {Number} options.version              QR Code version
 * @param {String} options.errorCorrectionLevel Error correction level
 * @param {Function} options.toSJISFunc         Helper func to convert utf8 to sjis
 */
exports.create = function create(data, options) {
  if (typeof data === 'undefined' || data === '') {
    throw new Error('No input text');
  }
  let errorCorrectionLevel = ECLevel.M;
  let version;
  let mask;
  if (typeof options !== 'undefined') {
    // Use higher error correction level as default
    errorCorrectionLevel = ECLevel.from(options.errorCorrectionLevel, ECLevel.M);
    version = Version.from(options.version);
    mask = MaskPattern.from(options.maskPattern);
    if (options.toSJISFunc) {
      Utils.setToSJISFunction(options.toSJISFunc);
    }
  }
  return createSymbol(data, version, errorCorrectionLevel, mask);
};

/***/ },

/***/ "./node_modules/qrcode/lib/core/reed-solomon-encoder.js"
/*!**************************************************************!*\
  !*** ./node_modules/qrcode/lib/core/reed-solomon-encoder.js ***!
  \**************************************************************/
(module, __unused_webpack_exports, __webpack_require__) {

const Polynomial = __webpack_require__(/*! ./polynomial */ "./node_modules/qrcode/lib/core/polynomial.js");
function ReedSolomonEncoder(degree) {
  this.genPoly = undefined;
  this.degree = degree;
  if (this.degree) this.initialize(this.degree);
}

/**
 * Initialize the encoder.
 * The input param should correspond to the number of error correction codewords.
 *
 * @param  {Number} degree
 */
ReedSolomonEncoder.prototype.initialize = function initialize(degree) {
  // create an irreducible generator polynomial
  this.degree = degree;
  this.genPoly = Polynomial.generateECPolynomial(this.degree);
};

/**
 * Encodes a chunk of data
 *
 * @param  {Uint8Array} data Buffer containing input data
 * @return {Uint8Array}      Buffer containing encoded data
 */
ReedSolomonEncoder.prototype.encode = function encode(data) {
  if (!this.genPoly) {
    throw new Error('Encoder not initialized');
  }

  // Calculate EC for this data block
  // extends data size to data+genPoly size
  const paddedData = new Uint8Array(data.length + this.degree);
  paddedData.set(data);

  // The error correction codewords are the remainder after dividing the data codewords
  // by a generator polynomial
  const remainder = Polynomial.mod(paddedData, this.genPoly);

  // return EC data blocks (last n byte, where n is the degree of genPoly)
  // If coefficients number in remainder are less than genPoly degree,
  // pad with 0s to the left to reach the needed number of coefficients
  const start = this.degree - remainder.length;
  if (start > 0) {
    const buff = new Uint8Array(this.degree);
    buff.set(remainder, start);
    return buff;
  }
  return remainder;
};
module.exports = ReedSolomonEncoder;

/***/ },

/***/ "./node_modules/qrcode/lib/core/regex.js"
/*!***********************************************!*\
  !*** ./node_modules/qrcode/lib/core/regex.js ***!
  \***********************************************/
(__unused_webpack_module, exports) {

const numeric = '[0-9]+';
const alphanumeric = '[A-Z $%*+\\-./:]+';
let kanji = '(?:[u3000-u303F]|[u3040-u309F]|[u30A0-u30FF]|' + '[uFF00-uFFEF]|[u4E00-u9FAF]|[u2605-u2606]|[u2190-u2195]|u203B|' + '[u2010u2015u2018u2019u2025u2026u201Cu201Du2225u2260]|' + '[u0391-u0451]|[u00A7u00A8u00B1u00B4u00D7u00F7])+';
kanji = kanji.replace(/u/g, '\\u');
const byte = '(?:(?![A-Z0-9 $%*+\\-./:]|' + kanji + ')(?:.|[\r\n]))+';
exports.KANJI = new RegExp(kanji, 'g');
exports.BYTE_KANJI = new RegExp('[^A-Z0-9 $%*+\\-./:]+', 'g');
exports.BYTE = new RegExp(byte, 'g');
exports.NUMERIC = new RegExp(numeric, 'g');
exports.ALPHANUMERIC = new RegExp(alphanumeric, 'g');
const TEST_KANJI = new RegExp('^' + kanji + '$');
const TEST_NUMERIC = new RegExp('^' + numeric + '$');
const TEST_ALPHANUMERIC = new RegExp('^[A-Z0-9 $%*+\\-./:]+$');
exports.testKanji = function testKanji(str) {
  return TEST_KANJI.test(str);
};
exports.testNumeric = function testNumeric(str) {
  return TEST_NUMERIC.test(str);
};
exports.testAlphanumeric = function testAlphanumeric(str) {
  return TEST_ALPHANUMERIC.test(str);
};

/***/ },

/***/ "./node_modules/qrcode/lib/core/segments.js"
/*!**************************************************!*\
  !*** ./node_modules/qrcode/lib/core/segments.js ***!
  \**************************************************/
(__unused_webpack_module, exports, __webpack_require__) {

const Mode = __webpack_require__(/*! ./mode */ "./node_modules/qrcode/lib/core/mode.js");
const NumericData = __webpack_require__(/*! ./numeric-data */ "./node_modules/qrcode/lib/core/numeric-data.js");
const AlphanumericData = __webpack_require__(/*! ./alphanumeric-data */ "./node_modules/qrcode/lib/core/alphanumeric-data.js");
const ByteData = __webpack_require__(/*! ./byte-data */ "./node_modules/qrcode/lib/core/byte-data.js");
const KanjiData = __webpack_require__(/*! ./kanji-data */ "./node_modules/qrcode/lib/core/kanji-data.js");
const Regex = __webpack_require__(/*! ./regex */ "./node_modules/qrcode/lib/core/regex.js");
const Utils = __webpack_require__(/*! ./utils */ "./node_modules/qrcode/lib/core/utils.js");
const dijkstra = __webpack_require__(/*! dijkstrajs */ "./node_modules/dijkstrajs/dijkstra.js");

/**
 * Returns UTF8 byte length
 *
 * @param  {String} str Input string
 * @return {Number}     Number of byte
 */
function getStringByteLength(str) {
  return unescape(encodeURIComponent(str)).length;
}

/**
 * Get a list of segments of the specified mode
 * from a string
 *
 * @param  {Mode}   mode Segment mode
 * @param  {String} str  String to process
 * @return {Array}       Array of object with segments data
 */
function getSegments(regex, mode, str) {
  const segments = [];
  let result;
  while ((result = regex.exec(str)) !== null) {
    segments.push({
      data: result[0],
      index: result.index,
      mode: mode,
      length: result[0].length
    });
  }
  return segments;
}

/**
 * Extracts a series of segments with the appropriate
 * modes from a string
 *
 * @param  {String} dataStr Input string
 * @return {Array}          Array of object with segments data
 */
function getSegmentsFromString(dataStr) {
  const numSegs = getSegments(Regex.NUMERIC, Mode.NUMERIC, dataStr);
  const alphaNumSegs = getSegments(Regex.ALPHANUMERIC, Mode.ALPHANUMERIC, dataStr);
  let byteSegs;
  let kanjiSegs;
  if (Utils.isKanjiModeEnabled()) {
    byteSegs = getSegments(Regex.BYTE, Mode.BYTE, dataStr);
    kanjiSegs = getSegments(Regex.KANJI, Mode.KANJI, dataStr);
  } else {
    byteSegs = getSegments(Regex.BYTE_KANJI, Mode.BYTE, dataStr);
    kanjiSegs = [];
  }
  const segs = numSegs.concat(alphaNumSegs, byteSegs, kanjiSegs);
  return segs.sort(function (s1, s2) {
    return s1.index - s2.index;
  }).map(function (obj) {
    return {
      data: obj.data,
      mode: obj.mode,
      length: obj.length
    };
  });
}

/**
 * Returns how many bits are needed to encode a string of
 * specified length with the specified mode
 *
 * @param  {Number} length String length
 * @param  {Mode} mode     Segment mode
 * @return {Number}        Bit length
 */
function getSegmentBitsLength(length, mode) {
  switch (mode) {
    case Mode.NUMERIC:
      return NumericData.getBitsLength(length);
    case Mode.ALPHANUMERIC:
      return AlphanumericData.getBitsLength(length);
    case Mode.KANJI:
      return KanjiData.getBitsLength(length);
    case Mode.BYTE:
      return ByteData.getBitsLength(length);
  }
}

/**
 * Merges adjacent segments which have the same mode
 *
 * @param  {Array} segs Array of object with segments data
 * @return {Array}      Array of object with segments data
 */
function mergeSegments(segs) {
  return segs.reduce(function (acc, curr) {
    const prevSeg = acc.length - 1 >= 0 ? acc[acc.length - 1] : null;
    if (prevSeg && prevSeg.mode === curr.mode) {
      acc[acc.length - 1].data += curr.data;
      return acc;
    }
    acc.push(curr);
    return acc;
  }, []);
}

/**
 * Generates a list of all possible nodes combination which
 * will be used to build a segments graph.
 *
 * Nodes are divided by groups. Each group will contain a list of all the modes
 * in which is possible to encode the given text.
 *
 * For example the text '12345' can be encoded as Numeric, Alphanumeric or Byte.
 * The group for '12345' will contain then 3 objects, one for each
 * possible encoding mode.
 *
 * Each node represents a possible segment.
 *
 * @param  {Array} segs Array of object with segments data
 * @return {Array}      Array of object with segments data
 */
function buildNodes(segs) {
  const nodes = [];
  for (let i = 0; i < segs.length; i++) {
    const seg = segs[i];
    switch (seg.mode) {
      case Mode.NUMERIC:
        nodes.push([seg, {
          data: seg.data,
          mode: Mode.ALPHANUMERIC,
          length: seg.length
        }, {
          data: seg.data,
          mode: Mode.BYTE,
          length: seg.length
        }]);
        break;
      case Mode.ALPHANUMERIC:
        nodes.push([seg, {
          data: seg.data,
          mode: Mode.BYTE,
          length: seg.length
        }]);
        break;
      case Mode.KANJI:
        nodes.push([seg, {
          data: seg.data,
          mode: Mode.BYTE,
          length: getStringByteLength(seg.data)
        }]);
        break;
      case Mode.BYTE:
        nodes.push([{
          data: seg.data,
          mode: Mode.BYTE,
          length: getStringByteLength(seg.data)
        }]);
    }
  }
  return nodes;
}

/**
 * Builds a graph from a list of nodes.
 * All segments in each node group will be connected with all the segments of
 * the next group and so on.
 *
 * At each connection will be assigned a weight depending on the
 * segment's byte length.
 *
 * @param  {Array} nodes    Array of object with segments data
 * @param  {Number} version QR Code version
 * @return {Object}         Graph of all possible segments
 */
function buildGraph(nodes, version) {
  const table = {};
  const graph = {
    start: {}
  };
  let prevNodeIds = ['start'];
  for (let i = 0; i < nodes.length; i++) {
    const nodeGroup = nodes[i];
    const currentNodeIds = [];
    for (let j = 0; j < nodeGroup.length; j++) {
      const node = nodeGroup[j];
      const key = '' + i + j;
      currentNodeIds.push(key);
      table[key] = {
        node: node,
        lastCount: 0
      };
      graph[key] = {};
      for (let n = 0; n < prevNodeIds.length; n++) {
        const prevNodeId = prevNodeIds[n];
        if (table[prevNodeId] && table[prevNodeId].node.mode === node.mode) {
          graph[prevNodeId][key] = getSegmentBitsLength(table[prevNodeId].lastCount + node.length, node.mode) - getSegmentBitsLength(table[prevNodeId].lastCount, node.mode);
          table[prevNodeId].lastCount += node.length;
        } else {
          if (table[prevNodeId]) table[prevNodeId].lastCount = node.length;
          graph[prevNodeId][key] = getSegmentBitsLength(node.length, node.mode) + 4 + Mode.getCharCountIndicator(node.mode, version); // switch cost
        }
      }
    }
    prevNodeIds = currentNodeIds;
  }
  for (let n = 0; n < prevNodeIds.length; n++) {
    graph[prevNodeIds[n]].end = 0;
  }
  return {
    map: graph,
    table: table
  };
}

/**
 * Builds a segment from a specified data and mode.
 * If a mode is not specified, the more suitable will be used.
 *
 * @param  {String} data             Input data
 * @param  {Mode | String} modesHint Data mode
 * @return {Segment}                 Segment
 */
function buildSingleSegment(data, modesHint) {
  let mode;
  const bestMode = Mode.getBestModeForData(data);
  mode = Mode.from(modesHint, bestMode);

  // Make sure data can be encoded
  if (mode !== Mode.BYTE && mode.bit < bestMode.bit) {
    throw new Error('"' + data + '"' + ' cannot be encoded with mode ' + Mode.toString(mode) + '.\n Suggested mode is: ' + Mode.toString(bestMode));
  }

  // Use Mode.BYTE if Kanji support is disabled
  if (mode === Mode.KANJI && !Utils.isKanjiModeEnabled()) {
    mode = Mode.BYTE;
  }
  switch (mode) {
    case Mode.NUMERIC:
      return new NumericData(data);
    case Mode.ALPHANUMERIC:
      return new AlphanumericData(data);
    case Mode.KANJI:
      return new KanjiData(data);
    case Mode.BYTE:
      return new ByteData(data);
  }
}

/**
 * Builds a list of segments from an array.
 * Array can contain Strings or Objects with segment's info.
 *
 * For each item which is a string, will be generated a segment with the given
 * string and the more appropriate encoding mode.
 *
 * For each item which is an object, will be generated a segment with the given
 * data and mode.
 * Objects must contain at least the property "data".
 * If property "mode" is not present, the more suitable mode will be used.
 *
 * @param  {Array} array Array of objects with segments data
 * @return {Array}       Array of Segments
 */
exports.fromArray = function fromArray(array) {
  return array.reduce(function (acc, seg) {
    if (typeof seg === 'string') {
      acc.push(buildSingleSegment(seg, null));
    } else if (seg.data) {
      acc.push(buildSingleSegment(seg.data, seg.mode));
    }
    return acc;
  }, []);
};

/**
 * Builds an optimized sequence of segments from a string,
 * which will produce the shortest possible bitstream.
 *
 * @param  {String} data    Input string
 * @param  {Number} version QR Code version
 * @return {Array}          Array of segments
 */
exports.fromString = function fromString(data, version) {
  const segs = getSegmentsFromString(data, Utils.isKanjiModeEnabled());
  const nodes = buildNodes(segs);
  const graph = buildGraph(nodes, version);
  const path = dijkstra.find_path(graph.map, 'start', 'end');
  const optimizedSegs = [];
  for (let i = 1; i < path.length - 1; i++) {
    optimizedSegs.push(graph.table[path[i]].node);
  }
  return exports.fromArray(mergeSegments(optimizedSegs));
};

/**
 * Splits a string in various segments with the modes which
 * best represent their content.
 * The produced segments are far from being optimized.
 * The output of this function is only used to estimate a QR Code version
 * which may contain the data.
 *
 * @param  {string} data Input string
 * @return {Array}       Array of segments
 */
exports.rawSplit = function rawSplit(data) {
  return exports.fromArray(getSegmentsFromString(data, Utils.isKanjiModeEnabled()));
};

/***/ },

/***/ "./node_modules/qrcode/lib/core/utils.js"
/*!***********************************************!*\
  !*** ./node_modules/qrcode/lib/core/utils.js ***!
  \***********************************************/
(__unused_webpack_module, exports) {

let toSJISFunction;
const CODEWORDS_COUNT = [0,
// Not used
26, 44, 70, 100, 134, 172, 196, 242, 292, 346, 404, 466, 532, 581, 655, 733, 815, 901, 991, 1085, 1156, 1258, 1364, 1474, 1588, 1706, 1828, 1921, 2051, 2185, 2323, 2465, 2611, 2761, 2876, 3034, 3196, 3362, 3532, 3706];

/**
 * Returns the QR Code size for the specified version
 *
 * @param  {Number} version QR Code version
 * @return {Number}         size of QR code
 */
exports.getSymbolSize = function getSymbolSize(version) {
  if (!version) throw new Error('"version" cannot be null or undefined');
  if (version < 1 || version > 40) throw new Error('"version" should be in range from 1 to 40');
  return version * 4 + 17;
};

/**
 * Returns the total number of codewords used to store data and EC information.
 *
 * @param  {Number} version QR Code version
 * @return {Number}         Data length in bits
 */
exports.getSymbolTotalCodewords = function getSymbolTotalCodewords(version) {
  return CODEWORDS_COUNT[version];
};

/**
 * Encode data with Bose-Chaudhuri-Hocquenghem
 *
 * @param  {Number} data Value to encode
 * @return {Number}      Encoded value
 */
exports.getBCHDigit = function (data) {
  let digit = 0;
  while (data !== 0) {
    digit++;
    data >>>= 1;
  }
  return digit;
};
exports.setToSJISFunction = function setToSJISFunction(f) {
  if (typeof f !== 'function') {
    throw new Error('"toSJISFunc" is not a valid function.');
  }
  toSJISFunction = f;
};
exports.isKanjiModeEnabled = function () {
  return typeof toSJISFunction !== 'undefined';
};
exports.toSJIS = function toSJIS(kanji) {
  return toSJISFunction(kanji);
};

/***/ },

/***/ "./node_modules/qrcode/lib/core/version-check.js"
/*!*******************************************************!*\
  !*** ./node_modules/qrcode/lib/core/version-check.js ***!
  \*******************************************************/
(__unused_webpack_module, exports) {

/**
 * Check if QR Code version is valid
 *
 * @param  {Number}  version QR Code version
 * @return {Boolean}         true if valid version, false otherwise
 */
exports.isValid = function isValid(version) {
  return !isNaN(version) && version >= 1 && version <= 40;
};

/***/ },

/***/ "./node_modules/qrcode/lib/core/version.js"
/*!*************************************************!*\
  !*** ./node_modules/qrcode/lib/core/version.js ***!
  \*************************************************/
(__unused_webpack_module, exports, __webpack_require__) {

const Utils = __webpack_require__(/*! ./utils */ "./node_modules/qrcode/lib/core/utils.js");
const ECCode = __webpack_require__(/*! ./error-correction-code */ "./node_modules/qrcode/lib/core/error-correction-code.js");
const ECLevel = __webpack_require__(/*! ./error-correction-level */ "./node_modules/qrcode/lib/core/error-correction-level.js");
const Mode = __webpack_require__(/*! ./mode */ "./node_modules/qrcode/lib/core/mode.js");
const VersionCheck = __webpack_require__(/*! ./version-check */ "./node_modules/qrcode/lib/core/version-check.js");

// Generator polynomial used to encode version information
const G18 = 1 << 12 | 1 << 11 | 1 << 10 | 1 << 9 | 1 << 8 | 1 << 5 | 1 << 2 | 1 << 0;
const G18_BCH = Utils.getBCHDigit(G18);
function getBestVersionForDataLength(mode, length, errorCorrectionLevel) {
  for (let currentVersion = 1; currentVersion <= 40; currentVersion++) {
    if (length <= exports.getCapacity(currentVersion, errorCorrectionLevel, mode)) {
      return currentVersion;
    }
  }
  return undefined;
}
function getReservedBitsCount(mode, version) {
  // Character count indicator + mode indicator bits
  return Mode.getCharCountIndicator(mode, version) + 4;
}
function getTotalBitsFromDataArray(segments, version) {
  let totalBits = 0;
  segments.forEach(function (data) {
    const reservedBits = getReservedBitsCount(data.mode, version);
    totalBits += reservedBits + data.getBitsLength();
  });
  return totalBits;
}
function getBestVersionForMixedData(segments, errorCorrectionLevel) {
  for (let currentVersion = 1; currentVersion <= 40; currentVersion++) {
    const length = getTotalBitsFromDataArray(segments, currentVersion);
    if (length <= exports.getCapacity(currentVersion, errorCorrectionLevel, Mode.MIXED)) {
      return currentVersion;
    }
  }
  return undefined;
}

/**
 * Returns version number from a value.
 * If value is not a valid version, returns defaultValue
 *
 * @param  {Number|String} value        QR Code version
 * @param  {Number}        defaultValue Fallback value
 * @return {Number}                     QR Code version number
 */
exports.from = function from(value, defaultValue) {
  if (VersionCheck.isValid(value)) {
    return parseInt(value, 10);
  }
  return defaultValue;
};

/**
 * Returns how much data can be stored with the specified QR code version
 * and error correction level
 *
 * @param  {Number} version              QR Code version (1-40)
 * @param  {Number} errorCorrectionLevel Error correction level
 * @param  {Mode}   mode                 Data mode
 * @return {Number}                      Quantity of storable data
 */
exports.getCapacity = function getCapacity(version, errorCorrectionLevel, mode) {
  if (!VersionCheck.isValid(version)) {
    throw new Error('Invalid QR Code version');
  }

  // Use Byte mode as default
  if (typeof mode === 'undefined') mode = Mode.BYTE;

  // Total codewords for this QR code version (Data + Error correction)
  const totalCodewords = Utils.getSymbolTotalCodewords(version);

  // Total number of error correction codewords
  const ecTotalCodewords = ECCode.getTotalCodewordsCount(version, errorCorrectionLevel);

  // Total number of data codewords
  const dataTotalCodewordsBits = (totalCodewords - ecTotalCodewords) * 8;
  if (mode === Mode.MIXED) return dataTotalCodewordsBits;
  const usableBits = dataTotalCodewordsBits - getReservedBitsCount(mode, version);

  // Return max number of storable codewords
  switch (mode) {
    case Mode.NUMERIC:
      return Math.floor(usableBits / 10 * 3);
    case Mode.ALPHANUMERIC:
      return Math.floor(usableBits / 11 * 2);
    case Mode.KANJI:
      return Math.floor(usableBits / 13);
    case Mode.BYTE:
    default:
      return Math.floor(usableBits / 8);
  }
};

/**
 * Returns the minimum version needed to contain the amount of data
 *
 * @param  {Segment} data                    Segment of data
 * @param  {Number} [errorCorrectionLevel=H] Error correction level
 * @param  {Mode} mode                       Data mode
 * @return {Number}                          QR Code version
 */
exports.getBestVersionForData = function getBestVersionForData(data, errorCorrectionLevel) {
  let seg;
  const ecl = ECLevel.from(errorCorrectionLevel, ECLevel.M);
  if (Array.isArray(data)) {
    if (data.length > 1) {
      return getBestVersionForMixedData(data, ecl);
    }
    if (data.length === 0) {
      return 1;
    }
    seg = data[0];
  } else {
    seg = data;
  }
  return getBestVersionForDataLength(seg.mode, seg.getLength(), ecl);
};

/**
 * Returns version information with relative error correction bits
 *
 * The version information is included in QR Code symbols of version 7 or larger.
 * It consists of an 18-bit sequence containing 6 data bits,
 * with 12 error correction bits calculated using the (18, 6) Golay code.
 *
 * @param  {Number} version QR Code version
 * @return {Number}         Encoded version info bits
 */
exports.getEncodedBits = function getEncodedBits(version) {
  if (!VersionCheck.isValid(version) || version < 7) {
    throw new Error('Invalid QR Code version');
  }
  let d = version << 12;
  while (Utils.getBCHDigit(d) - G18_BCH >= 0) {
    d ^= G18 << Utils.getBCHDigit(d) - G18_BCH;
  }
  return version << 12 | d;
};

/***/ },

/***/ "./node_modules/qrcode/lib/renderer/canvas.js"
/*!****************************************************!*\
  !*** ./node_modules/qrcode/lib/renderer/canvas.js ***!
  \****************************************************/
(__unused_webpack_module, exports, __webpack_require__) {

const Utils = __webpack_require__(/*! ./utils */ "./node_modules/qrcode/lib/renderer/utils.js");
function clearCanvas(ctx, canvas, size) {
  ctx.clearRect(0, 0, canvas.width, canvas.height);
  if (!canvas.style) canvas.style = {};
  canvas.height = size;
  canvas.width = size;
  canvas.style.height = size + 'px';
  canvas.style.width = size + 'px';
}
function getCanvasElement() {
  try {
    return document.createElement('canvas');
  } catch (e) {
    throw new Error('You need to specify a canvas element');
  }
}
exports.render = function render(qrData, canvas, options) {
  let opts = options;
  let canvasEl = canvas;
  if (typeof opts === 'undefined' && (!canvas || !canvas.getContext)) {
    opts = canvas;
    canvas = undefined;
  }
  if (!canvas) {
    canvasEl = getCanvasElement();
  }
  opts = Utils.getOptions(opts);
  const size = Utils.getImageWidth(qrData.modules.size, opts);
  const ctx = canvasEl.getContext('2d');
  const image = ctx.createImageData(size, size);
  Utils.qrToImageData(image.data, qrData, opts);
  clearCanvas(ctx, canvasEl, size);
  ctx.putImageData(image, 0, 0);
  return canvasEl;
};
exports.renderToDataURL = function renderToDataURL(qrData, canvas, options) {
  let opts = options;
  if (typeof opts === 'undefined' && (!canvas || !canvas.getContext)) {
    opts = canvas;
    canvas = undefined;
  }
  if (!opts) opts = {};
  const canvasEl = exports.render(qrData, canvas, opts);
  const type = opts.type || 'image/png';
  const rendererOpts = opts.rendererOpts || {};
  return canvasEl.toDataURL(type, rendererOpts.quality);
};

/***/ },

/***/ "./node_modules/qrcode/lib/renderer/svg-tag.js"
/*!*****************************************************!*\
  !*** ./node_modules/qrcode/lib/renderer/svg-tag.js ***!
  \*****************************************************/
(__unused_webpack_module, exports, __webpack_require__) {

const Utils = __webpack_require__(/*! ./utils */ "./node_modules/qrcode/lib/renderer/utils.js");
function getColorAttrib(color, attrib) {
  const alpha = color.a / 255;
  const str = attrib + '="' + color.hex + '"';
  return alpha < 1 ? str + ' ' + attrib + '-opacity="' + alpha.toFixed(2).slice(1) + '"' : str;
}
function svgCmd(cmd, x, y) {
  let str = cmd + x;
  if (typeof y !== 'undefined') str += ' ' + y;
  return str;
}
function qrToPath(data, size, margin) {
  let path = '';
  let moveBy = 0;
  let newRow = false;
  let lineLength = 0;
  for (let i = 0; i < data.length; i++) {
    const col = Math.floor(i % size);
    const row = Math.floor(i / size);
    if (!col && !newRow) newRow = true;
    if (data[i]) {
      lineLength++;
      if (!(i > 0 && col > 0 && data[i - 1])) {
        path += newRow ? svgCmd('M', col + margin, 0.5 + row + margin) : svgCmd('m', moveBy, 0);
        moveBy = 0;
        newRow = false;
      }
      if (!(col + 1 < size && data[i + 1])) {
        path += svgCmd('h', lineLength);
        lineLength = 0;
      }
    } else {
      moveBy++;
    }
  }
  return path;
}
exports.render = function render(qrData, options, cb) {
  const opts = Utils.getOptions(options);
  const size = qrData.modules.size;
  const data = qrData.modules.data;
  const qrcodesize = size + opts.margin * 2;
  const bg = !opts.color.light.a ? '' : '<path ' + getColorAttrib(opts.color.light, 'fill') + ' d="M0 0h' + qrcodesize + 'v' + qrcodesize + 'H0z"/>';
  const path = '<path ' + getColorAttrib(opts.color.dark, 'stroke') + ' d="' + qrToPath(data, size, opts.margin) + '"/>';
  const viewBox = 'viewBox="' + '0 0 ' + qrcodesize + ' ' + qrcodesize + '"';
  const width = !opts.width ? '' : 'width="' + opts.width + '" height="' + opts.width + '" ';
  const svgTag = '<svg xmlns="http://www.w3.org/2000/svg" ' + width + viewBox + ' shape-rendering="crispEdges">' + bg + path + '</svg>\n';
  if (typeof cb === 'function') {
    cb(null, svgTag);
  }
  return svgTag;
};

/***/ },

/***/ "./node_modules/qrcode/lib/renderer/utils.js"
/*!***************************************************!*\
  !*** ./node_modules/qrcode/lib/renderer/utils.js ***!
  \***************************************************/
(__unused_webpack_module, exports) {

function hex2rgba(hex) {
  if (typeof hex === 'number') {
    hex = hex.toString();
  }
  if (typeof hex !== 'string') {
    throw new Error('Color should be defined as hex string');
  }
  let hexCode = hex.slice().replace('#', '').split('');
  if (hexCode.length < 3 || hexCode.length === 5 || hexCode.length > 8) {
    throw new Error('Invalid hex color: ' + hex);
  }

  // Convert from short to long form (fff -> ffffff)
  if (hexCode.length === 3 || hexCode.length === 4) {
    hexCode = Array.prototype.concat.apply([], hexCode.map(function (c) {
      return [c, c];
    }));
  }

  // Add default alpha value
  if (hexCode.length === 6) hexCode.push('F', 'F');
  const hexValue = parseInt(hexCode.join(''), 16);
  return {
    r: hexValue >> 24 & 255,
    g: hexValue >> 16 & 255,
    b: hexValue >> 8 & 255,
    a: hexValue & 255,
    hex: '#' + hexCode.slice(0, 6).join('')
  };
}
exports.getOptions = function getOptions(options) {
  if (!options) options = {};
  if (!options.color) options.color = {};
  const margin = typeof options.margin === 'undefined' || options.margin === null || options.margin < 0 ? 4 : options.margin;
  const width = options.width && options.width >= 21 ? options.width : undefined;
  const scale = options.scale || 4;
  return {
    width: width,
    scale: width ? 4 : scale,
    margin: margin,
    color: {
      dark: hex2rgba(options.color.dark || '#000000ff'),
      light: hex2rgba(options.color.light || '#ffffffff')
    },
    type: options.type,
    rendererOpts: options.rendererOpts || {}
  };
};
exports.getScale = function getScale(qrSize, opts) {
  return opts.width && opts.width >= qrSize + opts.margin * 2 ? opts.width / (qrSize + opts.margin * 2) : opts.scale;
};
exports.getImageWidth = function getImageWidth(qrSize, opts) {
  const scale = exports.getScale(qrSize, opts);
  return Math.floor((qrSize + opts.margin * 2) * scale);
};
exports.qrToImageData = function qrToImageData(imgData, qr, opts) {
  const size = qr.modules.size;
  const data = qr.modules.data;
  const scale = exports.getScale(size, opts);
  const symbolSize = Math.floor((size + opts.margin * 2) * scale);
  const scaledMargin = opts.margin * scale;
  const palette = [opts.color.light, opts.color.dark];
  for (let i = 0; i < symbolSize; i++) {
    for (let j = 0; j < symbolSize; j++) {
      let posDst = (i * symbolSize + j) * 4;
      let pxColor = opts.color.light;
      if (i >= scaledMargin && j >= scaledMargin && i < symbolSize - scaledMargin && j < symbolSize - scaledMargin) {
        const iSrc = Math.floor((i - scaledMargin) / scale);
        const jSrc = Math.floor((j - scaledMargin) / scale);
        pxColor = palette[data[iSrc * size + jSrc] ? 1 : 0];
      }
      imgData[posDst++] = pxColor.r;
      imgData[posDst++] = pxColor.g;
      imgData[posDst++] = pxColor.b;
      imgData[posDst] = pxColor.a;
    }
  }
};

/***/ },

/***/ "./node_modules/wwpass-frontend/src/ab.js"
/*!************************************************!*\
  !*** ./node_modules/wwpass-frontend/src/ab.js ***!
  \************************************************/
(__unused_webpack_module, __webpack_exports__, __webpack_require__) {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   ab2str: () => (/* binding */ ab2str),
/* harmony export */   abToB64: () => (/* binding */ abToB64),
/* harmony export */   b64ToAb: () => (/* binding */ b64ToAb),
/* harmony export */   str2ab: () => (/* binding */ str2ab)
/* harmony export */ });
/* Conversions between String, ArrayBuffer and Base64 Strings */

const abToB64 = data => btoa(String.fromCharCode.apply(null, new Uint8Array(data)));
const b64ToAb = base64 => {
  const s = atob(base64);
  const bytes = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i += 1) {
    bytes[i] = s.charCodeAt(i);
  }
  return bytes.buffer;
};
const ab2str = buf => String.fromCharCode.apply(null, new Uint16Array(buf));
const str2ab = str => {
  const buf = new ArrayBuffer(str.length * 2); // 2 bytes for each char
  const bufView = new Uint16Array(buf);
  for (let i = 0, strLen = str.length; i < strLen; i += 1) {
    bufView[i] = str.charCodeAt(i);
  }
  return buf;
};


/***/ },

/***/ "./node_modules/wwpass-frontend/src/auth.js"
/*!**************************************************!*\
  !*** ./node_modules/wwpass-frontend/src/auth.js ***!
  \**************************************************/
(__unused_webpack_module, __webpack_exports__, __webpack_require__) {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   authInit: () => (/* binding */ authInit),
/* harmony export */   wwpassMobileAuth: () => (/* binding */ wwpassMobileAuth)
/* harmony export */ });
/* harmony import */ var _util__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! ./util */ "./node_modules/wwpass-frontend/src/util.js");
/* harmony import */ var _navigation__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! ./navigation */ "./node_modules/wwpass-frontend/src/navigation.js");
/* harmony import */ var _constants__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(/*! ./constants */ "./node_modules/wwpass-frontend/src/constants.js");
/* harmony import */ var _mobile_auth__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(/*! ./mobile/auth */ "./node_modules/wwpass-frontend/src/mobile/auth.js");
/* harmony import */ var _urls__WEBPACK_IMPORTED_MODULE_4__ = __webpack_require__(/*! ./urls */ "./node_modules/wwpass-frontend/src/urls.js");
/* harmony import */ var _open__WEBPACK_IMPORTED_MODULE_5__ = __webpack_require__(/*! ./open */ "./node_modules/wwpass-frontend/src/open.js");
/* harmony import */ var _ticket__WEBPACK_IMPORTED_MODULE_6__ = __webpack_require__(/*! ./ticket */ "./node_modules/wwpass-frontend/src/ticket.js");








/*
 * WWPass auth with mobile PassKey
 *
options = {
    'ticketURL': undefined, // string
    'callbackURL': undefined, // string
    'uiType': 'auto', // 'auto' | 'button' | 'qrcode'
    'uiSwitch': 'auto', // 'auto' | 'always' | 'never'
    'log': function (message) || console.log, // another log handler
}
 */
const wwpassMobileAuth = async initialOptions => {
  const defaultOptions = {
    ticketURL: undefined,
    callbackURL: undefined,
    uiType: 'auto',
    uiSwitch: 'auto',
    version: _constants__WEBPACK_IMPORTED_MODULE_2__.PROTOCOL_VERSION,
    ppx: 'wwp_',
    spfewsAddress: 'wss://spfews.wwpass.com',
    qrcodeStyle: {
      width: 256,
      prefix: 'wwp_'
    },
    log: () => {}
  };
  const options = {
    ...defaultOptions,
    ...initialOptions
  };
  options.qrcodeStyle = {
    ...defaultOptions.qrcodeStyle,
    ...initialOptions.qrcodeStyle
  };
  options.dh = (0,_urls__WEBPACK_IMPORTED_MODULE_4__.getCurrentDh)(window) || 0;
  if (!options.ticketURL) {
    throw Error('ticketURL not found');
  }
  if (!options.callbackURL) {
    throw Error('callbackURL not found');
  }
  if (!options.qrcode) {
    throw Error('Element not found');
  }
  let executor = null;
  switch (options.uiType) {
    case 'button':
      executor = _mobile_auth__WEBPACK_IMPORTED_MODULE_3__.appAuth;
      break;
    case 'qrcode':
      executor = _mobile_auth__WEBPACK_IMPORTED_MODULE_3__.qrCodeAndPasskeyAuth;
      break;
    case 'auto':
    default:
      executor = (0,_mobile_auth__WEBPACK_IMPORTED_MODULE_3__.isMobile)() ? _mobile_auth__WEBPACK_IMPORTED_MODULE_3__.appAuth : _mobile_auth__WEBPACK_IMPORTED_MODULE_3__.qrCodeAndPasskeyAuth;
      break;
  }
  if (options.uiCallback) {
    options.uiCallback(executor === _mobile_auth__WEBPACK_IMPORTED_MODULE_3__.appAuth ? {
      button: true
    } : {
      qrcode: true
    });
  }

  // Continue until an exception is thrown or qrcode element is removed from DOM
  do {
    // eslint-disable-next-line no-await-in-loop
    const result = await executor(options);
    if (options.uiCallback) options.uiCallback(result);
    if (result.away) {
      // eslint-disable-next-line no-await-in-loop
      await (0,_mobile_auth__WEBPACK_IMPORTED_MODULE_3__.redirectToWWPassApp)(options, result);
    } else if (result.button) {
      executor = _mobile_auth__WEBPACK_IMPORTED_MODULE_3__.appAuth;
    } else if (result.qrcode) {
      executor = _mobile_auth__WEBPACK_IMPORTED_MODULE_3__.qrCodeAndPasskeyAuth;
    }
    if (result.ticket) {
      (0,_navigation__WEBPACK_IMPORTED_MODULE_1__["default"])(result);
    }
    if (!result.refresh) {
      if (options.once || result.status === _constants__WEBPACK_IMPORTED_MODULE_2__.WWPASS_STATUS.TERMINAL_ERROR) return result;
    }
  } while (document.documentElement.contains(options.qrcode));
  return {
    status: _constants__WEBPACK_IMPORTED_MODULE_2__.WWPASS_STATUS.TERMINAL_ERROR,
    reason: 'QRCode element is not in DOM'
  };
};
const getForceScheme = (universal = false, forceScheme = false) => {
  if (forceScheme) {
    return false;
  }
  return universal;
};
const authInit = initialOptions => {
  const defaultOptions = {
    ticketURL: '',
    callbackURL: '',
    hw: false,
    ppx: 'wwp_',
    version: _constants__WEBPACK_IMPORTED_MODULE_2__.PROTOCOL_VERSION,
    fastForward: false,
    log: () => {}
  };
  const urlParams = new URLSearchParams(window.location.search);
  const wwpassAppForceScheme = urlParams.get('wwpass_app_force_scheme');
  const options = {
    ...defaultOptions,
    ...initialOptions,
    ...{
      universal: getForceScheme(initialOptions.universal, wwpassAppForceScheme)
    }
  };
  if (typeof options.callbackURL === 'string') {
    options.callbackURL = (0,_util__WEBPACK_IMPORTED_MODULE_0__.absolutePath)(options.callbackURL);
  }
  if (options.fastForward) {
    // get search params

    const wwpassAppForceAuth = urlParams.get('wwpass_app_force_auth') || false;
    if (wwpassAppForceAuth) {
      return (0,_mobile_auth__WEBPACK_IMPORTED_MODULE_3__.getTicket)(options.ticketURL).then(json => {
        const response = (0,_ticket__WEBPACK_IMPORTED_MODULE_6__.ticketAdapter)(json);
        const {
          ticket
        } = response;
        options.ticket = ticket;
        (0,_open__WEBPACK_IMPORTED_MODULE_5__["default"])(options);
        setTimeout(window.close, 5000);
      });
    }
  }
  options.passkeyButton = typeof options.passkey === 'string' ? document.querySelector(options.passkey) : options.passkey;
  options.qrcode = typeof options.qrcode === 'string' ? document.querySelector(options.qrcode) : options.qrcode;
  return wwpassMobileAuth(options);
};


/***/ },

/***/ "./node_modules/wwpass-frontend/src/constants.js"
/*!*******************************************************!*\
  !*** ./node_modules/wwpass-frontend/src/constants.js ***!
  \*******************************************************/
(__unused_webpack_module, __webpack_exports__, __webpack_require__) {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   PROTOCOL_VERSION: () => (/* binding */ PROTOCOL_VERSION),
/* harmony export */   WWPASS_KEY_TYPE_ANY: () => (/* binding */ WWPASS_KEY_TYPE_ANY),
/* harmony export */   WWPASS_KEY_TYPE_BLANK: () => (/* binding */ WWPASS_KEY_TYPE_BLANK),
/* harmony export */   WWPASS_KEY_TYPE_BLANK2NDSERVICE: () => (/* binding */ WWPASS_KEY_TYPE_BLANK2NDSERVICE),
/* harmony export */   WWPASS_KEY_TYPE_BLANKPASSKEY: () => (/* binding */ WWPASS_KEY_TYPE_BLANKPASSKEY),
/* harmony export */   WWPASS_KEY_TYPE_BLANKSERVICE: () => (/* binding */ WWPASS_KEY_TYPE_BLANKSERVICE),
/* harmony export */   WWPASS_KEY_TYPE_DEFAULT: () => (/* binding */ WWPASS_KEY_TYPE_DEFAULT),
/* harmony export */   WWPASS_KEY_TYPE_PASSKEY: () => (/* binding */ WWPASS_KEY_TYPE_PASSKEY),
/* harmony export */   WWPASS_KEY_TYPE_SERVICE: () => (/* binding */ WWPASS_KEY_TYPE_SERVICE),
/* harmony export */   WWPASS_OK_MSG: () => (/* binding */ WWPASS_OK_MSG),
/* harmony export */   WWPASS_STATUS: () => (/* binding */ WWPASS_STATUS)
/* harmony export */ });
/* Constants */
/* Status codes */
const WWPASS_OK_MSG = 'OK';
const WWPASS_STATUS = {
  CONTINUE: 100,
  OK: 200,
  INTERNAL_ERROR: 400,
  ALREADY_PERSONALIZED: 401,
  PASSWORD_MISMATCH: 402,
  PASSWORD_LOCKOUT: 403,
  WRONG_KEY: 404,
  WRONG_KEY_SECOND: 405,
  NOT_A_KEY: 406,
  NOT_A_KEY_SECOND: 407,
  KEY_DISABLED: 408,
  NOT_ALLOWED: 409,
  BLANK_TOKEN: 410,
  BLANK_SECOND_TOKEN: 411,
  ACTIVITY_PROFILE_LOCKED: 412,
  SSL_REQUIRED: 413,
  BLANK_NORMAL_TOKEN: 414,
  BLANK_SECOND_NORMAL_TOKEN: 415,
  BLANK_MASTER_TOKEN: 416,
  BLANK_SECOND_MASTER_TOKEN: 417,
  NOT_ACTIVATED_TOKEN: 418,
  NOT_ACTIVATED_SECOND_TOKEN: 419,
  WRONG_KEY_SET: 420,
  NO_VERIFIER: 421,
  INCOMPLETE_KEYSET: 422,
  INVALID_TICKET: 423,
  SAME_TOKEN: 424,
  NO_RECOVERY_INFO: 425,
  BAD_RECOVERY_REQUEST: 426,
  RECOVERY_FAILED: 427,
  TERMINAL_ERROR: 500,
  TERMINAL_NOT_FOUND: 501,
  TERMINAL_BAD_REQUEST: 502,
  NO_CONNECTION: 503,
  NETWORK_ERROR: 504,
  PROTOCOL_ERROR: 505,
  UNKNOWN_HANDLER: 506,
  TERMINAL_CANCELED: 590,
  TIMEOUT: 600,
  TICKET_TIMEOUT: 601,
  USER_REJECT: 603,
  NO_AUTH_INTERFACES_FOUND: 604,
  TERMINAL_TIMEOUT: 605,
  UNSUPPORTED_PLATFORM: 606
};
const WWPASS_KEY_TYPE_ANY = '';
const WWPASS_KEY_TYPE_PASSKEY = 'passkey';
const WWPASS_KEY_TYPE_SERVICE = 'service';
const WWPASS_KEY_TYPE_BLANK = 'blank';
const WWPASS_KEY_TYPE_BLANKPASSKEY = 'blankpasskey';
const WWPASS_KEY_TYPE_BLANKSERVICE = 'blankservice';
const WWPASS_KEY_TYPE_BLANK2NDSERVICE = 'blank2ndservice';
const WWPASS_KEY_TYPE_DEFAULT = WWPASS_KEY_TYPE_PASSKEY;
const PROTOCOL_VERSION = 2;

/***/ },

/***/ "./node_modules/wwpass-frontend/src/crypto.js"
/*!****************************************************!*\
  !*** ./node_modules/wwpass-frontend/src/crypto.js ***!
  \****************************************************/
(__unused_webpack_module, __webpack_exports__, __webpack_require__) {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   decrypt: () => (/* binding */ decrypt),
/* harmony export */   encodeClientNonce: () => (/* binding */ encodeClientNonce),
/* harmony export */   encrypt: () => (/* binding */ encrypt),
/* harmony export */   exportKey: () => (/* binding */ exportKey),
/* harmony export */   generateKey: () => (/* binding */ generateKey),
/* harmony export */   getRandomData: () => (/* binding */ getRandomData),
/* harmony export */   haveCryptoAPI: () => (/* binding */ haveCryptoAPI),
/* harmony export */   importKey: () => (/* binding */ importKey),
/* harmony export */   sha256: () => (/* binding */ sha256),
/* harmony export */   subtle: () => (/* binding */ subtle)
/* harmony export */ });
/* harmony import */ var _ab__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! ./ab */ "./node_modules/wwpass-frontend/src/ab.js");
/* harmony import */ var _util__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! ./util */ "./node_modules/wwpass-frontend/src/util.js");


const crypto = window.crypto || window.msCrypto;
const subtle = crypto ? crypto.webkitSubtle || crypto.subtle : null;
const encodeClientNonce = key => (0,_ab__WEBPACK_IMPORTED_MODULE_0__.abToB64)(key).replace(/\+/g, '-').replace(/[/]/g, '.').replace(/=/g, '_');

// These functions cannot be just reexported. We have to capture "subtle"
const encrypt = (options, key, data) => subtle.encrypt(options, key, data);
const decrypt = (options, key, data) => subtle.decrypt(options, key, data);
const exportKey = key => subtle.exportKey('raw', key);
const importKey = (key, algoritm, extractable, operations) => subtle.importKey('raw', key, algoritm, extractable, operations);
const getRandomData = buffer => crypto.getRandomValues(buffer);
const generateKey = () => subtle.generateKey({
  name: 'AES-CBC',
  length: 256
}, true,
// is extractable
['encrypt', 'decrypt']);
const sha256 = async str => (0,_util__WEBPACK_IMPORTED_MODULE_1__.hexlify)(await subtle.digest({
  name: 'SHA-256'
}, (0,_ab__WEBPACK_IMPORTED_MODULE_0__.str2ab)(str)));
const haveCryptoAPI = Boolean(subtle);


/***/ },

/***/ "./node_modules/wwpass-frontend/src/error.js"
/*!***************************************************!*\
  !*** ./node_modules/wwpass-frontend/src/error.js ***!
  \***************************************************/
(__unused_webpack_module, __webpack_exports__, __webpack_require__) {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   "default": () => (__WEBPACK_DEFAULT_EXPORT__)
/* harmony export */ });
class WWPassError extends Error {
  constructor(code, ...args) {
    super(args, WWPassError);
    Error.captureStackTrace(this, WWPassError);
    this.code = code;
  }
  toString() {
    return `${this.name}(${this.code}): ${this.message}`;
  }
}
/* harmony default export */ const __WEBPACK_DEFAULT_EXPORT__ = (WWPassError);

/***/ },

/***/ "./node_modules/wwpass-frontend/src/getticket.js"
/*!*******************************************************!*\
  !*** ./node_modules/wwpass-frontend/src/getticket.js ***!
  \*******************************************************/
(__unused_webpack_module, __webpack_exports__, __webpack_require__) {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   getTicket: () => (/* binding */ getTicket),
/* harmony export */   updateTicket: () => (/* binding */ updateTicket)
/* harmony export */ });
/* harmony import */ var _util__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! ./util */ "./node_modules/wwpass-frontend/src/util.js");
/* harmony import */ var _mobile_wwpass_websocket__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! ./mobile/wwpass.websocket */ "./node_modules/wwpass-frontend/src/mobile/wwpass.websocket.js");
/* harmony import */ var _nonce__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(/*! ./nonce */ "./node_modules/wwpass-frontend/src/nonce.js");
/* harmony import */ var _ticket__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(/*! ./ticket */ "./node_modules/wwpass-frontend/src/ticket.js");




const noCacheHeaders = {
  pragma: 'no-cache',
  'cache-control': 'no-cache'
};
const getTicket = async url => {
  let response = null;
  for (let i = 0; i < 3; i += 1) {
    try {
      // eslint-disable-next-line no-await-in-loop
      response = await fetch(url, {
        cache: 'no-store',
        headers: noCacheHeaders
      });
      if (response != null && response.ok) break;
    } catch (err) {
      /* Probably fetch() was cancelled because of page closing or user cancelling loads */
      // eslint-disable-next-line no-await-in-loop
      await (0,_util__WEBPACK_IMPORTED_MODULE_0__.wait)(100);
    }
  }
  if (response === null || !response.ok) {
    throw Error(`Error fetching ticket from "${url}": ${response.statusText}`);
  }
  return response.json();
};

/* updateTicket should be called when the client wants to extend the session beyond
  ticket's TTL. The URL handler on the server should use putTicket to get new ticket
  whith the same credentials as the old one. The URL should return JSON object:
  {"oldTicket": "<previous_ticket>", "newTicket": "<new_ticket>", "ttl": <new_ticket_ttl>}
  The functions ultimately resolves to:
  {"ticket": "<new_ticket>", "ttl": <new_ticket_ttl>}
*/
const updateTicket = url => fetch(url, {
  cache: 'no-store',
  headers: noCacheHeaders
}).then(response => {
  if (!response.ok) {
    throw Error(`Error updating ticket from "${url}": ${response.statusText}`);
  }
  return response.json();
}).then(response => {
  if (!response.newTicket || !response.oldTicket || !response.ttl) {
    throw Error(`Invalid response ot updateTicket: ${response}`);
  }
  const result = {
    ticket: response.newTicket,
    ttl: response.ttl
  };
  if (!(0,_ticket__WEBPACK_IMPORTED_MODULE_3__.isClientKeyTicket)(response.newTicket)) {
    return result;
  }
  const websocketPool = new _mobile_wwpass_websocket__WEBPACK_IMPORTED_MODULE_1__["default"]({
    clientKeyOnly: true
  });
  websocketPool.watchTicket(response.newTicket);
  // We have to call getWebSocketResult and getClientNonce to check for Nonce and update
  // TTL on original ticket
  return websocketPool.promise.then(wsResult => {
    if (!wsResult.clientKey) {
      throw Error(`No client key associated with the ticket ${response.newTicket}`);
    }
    return (0,_nonce__WEBPACK_IMPORTED_MODULE_2__.getClientNonce)(wsResult.originalTicket ? wsResult.originalTicket : response.newTicket, wsResult.ttl);
  }).then(() => result);
});


/***/ },

/***/ "./node_modules/wwpass-frontend/src/lib.js"
/*!*************************************************!*\
  !*** ./node_modules/wwpass-frontend/src/lib.js ***!
  \*************************************************/
(__unused_webpack_module, __webpack_exports__, __webpack_require__) {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   QRCodeAuth: () => (/* reexport safe */ _auth__WEBPACK_IMPORTED_MODULE_2__.wwpassMobileAuth),
/* harmony export */   WWPASS_STATUS: () => (/* reexport safe */ _constants__WEBPACK_IMPORTED_MODULE_7__.WWPASS_STATUS),
/* harmony export */   authInit: () => (/* reexport safe */ _auth__WEBPACK_IMPORTED_MODULE_2__.authInit),
/* harmony export */   copyClientNonce: () => (/* reexport safe */ _nonce__WEBPACK_IMPORTED_MODULE_1__.copyClientNonce),
/* harmony export */   cryptoPromise: () => (/* reexport safe */ _wwpass_crypto__WEBPACK_IMPORTED_MODULE_0__.WWPassCryptoPromise),
/* harmony export */   isClientKeyTicket: () => (/* reexport safe */ _ticket__WEBPACK_IMPORTED_MODULE_5__.isClientKeyTicket),
/* harmony export */   openWithTicket: () => (/* reexport safe */ _open__WEBPACK_IMPORTED_MODULE_3__["default"]),
/* harmony export */   passkeyAuth: () => (/* reexport safe */ _passkey_auth__WEBPACK_IMPORTED_MODULE_4__.wwpassPasskeyAuth),
/* harmony export */   pluginPresent: () => (/* reexport safe */ _passkey_auth__WEBPACK_IMPORTED_MODULE_4__.pluginPresent),
/* harmony export */   updateTicket: () => (/* reexport safe */ _getticket__WEBPACK_IMPORTED_MODULE_6__.updateTicket),
/* harmony export */   waitForRemoval: () => (/* reexport safe */ _passkey_auth__WEBPACK_IMPORTED_MODULE_4__.waitForRemoval)
/* harmony export */ });
/* harmony import */ var _wwpass_crypto__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! ./wwpass.crypto */ "./node_modules/wwpass-frontend/src/wwpass.crypto.js");
/* harmony import */ var _nonce__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! ./nonce */ "./node_modules/wwpass-frontend/src/nonce.js");
/* harmony import */ var _auth__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(/*! ./auth */ "./node_modules/wwpass-frontend/src/auth.js");
/* harmony import */ var _open__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(/*! ./open */ "./node_modules/wwpass-frontend/src/open.js");
/* harmony import */ var _passkey_auth__WEBPACK_IMPORTED_MODULE_4__ = __webpack_require__(/*! ./passkey/auth */ "./node_modules/wwpass-frontend/src/passkey/auth.js");
/* harmony import */ var _ticket__WEBPACK_IMPORTED_MODULE_5__ = __webpack_require__(/*! ./ticket */ "./node_modules/wwpass-frontend/src/ticket.js");
/* harmony import */ var _getticket__WEBPACK_IMPORTED_MODULE_6__ = __webpack_require__(/*! ./getticket */ "./node_modules/wwpass-frontend/src/getticket.js");
/* harmony import */ var _constants__WEBPACK_IMPORTED_MODULE_7__ = __webpack_require__(/*! ./constants */ "./node_modules/wwpass-frontend/src/constants.js");










/***/ },

/***/ "./node_modules/wwpass-frontend/src/mobile/auth.js"
/*!*********************************************************!*\
  !*** ./node_modules/wwpass-frontend/src/mobile/auth.js ***!
  \*********************************************************/
(__unused_webpack_module, __webpack_exports__, __webpack_require__) {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   appAuth: () => (/* binding */ appAuth),
/* harmony export */   getTicket: () => (/* reexport safe */ _getticket__WEBPACK_IMPORTED_MODULE_4__.getTicket),
/* harmony export */   isMobile: () => (/* binding */ isMobile),
/* harmony export */   qrCodeAndPasskeyAuth: () => (/* binding */ qrCodeAndPasskeyAuth),
/* harmony export */   redirectToWWPassApp: () => (/* binding */ redirectToWWPassApp)
/* harmony export */ });
/* harmony import */ var _passkey_auth__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! ../passkey/auth */ "./node_modules/wwpass-frontend/src/passkey/auth.js");
/* harmony import */ var _wwpass_websocket__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! ./wwpass.websocket */ "./node_modules/wwpass-frontend/src/mobile/wwpass.websocket.js");
/* harmony import */ var _util__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(/*! ../util */ "./node_modules/wwpass-frontend/src/util.js");
/* harmony import */ var _ticket__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(/*! ../ticket */ "./node_modules/wwpass-frontend/src/ticket.js");
/* harmony import */ var _getticket__WEBPACK_IMPORTED_MODULE_4__ = __webpack_require__(/*! ../getticket */ "./node_modules/wwpass-frontend/src/getticket.js");
/* harmony import */ var _crypto__WEBPACK_IMPORTED_MODULE_5__ = __webpack_require__(/*! ../crypto */ "./node_modules/wwpass-frontend/src/crypto.js");
/* harmony import */ var _nonce__WEBPACK_IMPORTED_MODULE_6__ = __webpack_require__(/*! ../nonce */ "./node_modules/wwpass-frontend/src/nonce.js");
/* harmony import */ var _constants__WEBPACK_IMPORTED_MODULE_7__ = __webpack_require__(/*! ../constants */ "./node_modules/wwpass-frontend/src/constants.js");
/* harmony import */ var _ui__WEBPACK_IMPORTED_MODULE_8__ = __webpack_require__(/*! ./ui */ "./node_modules/wwpass-frontend/src/mobile/ui.js");
/* harmony import */ var _urls__WEBPACK_IMPORTED_MODULE_9__ = __webpack_require__(/*! ../urls */ "./node_modules/wwpass-frontend/src/urls.js");










const METHOD_KEY_NAME = 'wwpass.auth.method';
const METHOD_QRCODE = 'qrcode';
const WAIT_ON_ERROR = 500;
const isMobile = () => navigator && ('userAgent' in navigator && navigator.userAgent.match(/iPhone|iPod|iPad|Android/i) || navigator.maxTouchPoints > 1 && navigator.platform === 'MacIntel');
const redirectToWWPassApp = async (options, authResult) => {
  const json = await (0,_getticket__WEBPACK_IMPORTED_MODULE_4__.getTicket)(options.ticketURL);
  const response = (0,_ticket__WEBPACK_IMPORTED_MODULE_3__.ticketAdapter)(json);
  const {
    ticket
  } = response;
  const {
    ttl
  } = response;
  const key = await (0,_nonce__WEBPACK_IMPORTED_MODULE_6__.getClientNonceIfNeeded)(ticket, ttl);
  // eslint-disable-next-line no-param-reassign
  authResult.linkElement.href = (0,_urls__WEBPACK_IMPORTED_MODULE_9__.getUniversalURL)({
    ticket,
    callbackURL: options.callbackURL,
    clientKey: key ? (0,_crypto__WEBPACK_IMPORTED_MODULE_5__.encodeClientNonce)(key) : undefined,
    ppx: options.ppx,
    version: _constants__WEBPACK_IMPORTED_MODULE_7__.PROTOCOL_VERSION,
    universal: options.universal || false,
    dh: options.dh
  });
  authResult.linkElement.click();
};
const appAuth = initialOptions => {
  const defaultOptions = {
    universal: false,
    ticketURL: undefined,
    callbackURL: undefined,
    version: _constants__WEBPACK_IMPORTED_MODULE_7__.PROTOCOL_VERSION,
    ppx: 'wwp_',
    log: () => {}
  };
  const options = {
    ...defaultOptions,
    ...initialOptions
  };
  return (0,_ui__WEBPACK_IMPORTED_MODULE_8__.sameDeviceLogin)(options, null, null, true);
};
const qrCodeAuth = async (options, websocketPool) => {
  // Continue until an exception is thrown or qrcode element is removed from DOM
  do {
    try {
      (0,_ui__WEBPACK_IMPORTED_MODULE_8__.clearQRCode)(options.qrcode, options.qrcodeStyle);
      // eslint-disable-next-line no-await-in-loop
      const json = await (0,_getticket__WEBPACK_IMPORTED_MODULE_4__.getTicket)(options.ticketURL);
      const response = (0,_ticket__WEBPACK_IMPORTED_MODULE_3__.ticketAdapter)(json);
      const {
        ticket
      } = response;
      const {
        ttl
      } = response;
      // eslint-disable-next-line no-await-in-loop
      const key = await (0,_nonce__WEBPACK_IMPORTED_MODULE_6__.getClientNonceIfNeeded)(ticket, ttl);
      const wwpassURLoptions = {
        ticket,
        shortTicket: (0,_ticket__WEBPACK_IMPORTED_MODULE_3__.getShortTicketForm)(ticket),
        callbackURL: options.callbackURL,
        ppx: options.ppx,
        version: _constants__WEBPACK_IMPORTED_MODULE_7__.PROTOCOL_VERSION,
        clientKey: key ? (0,_crypto__WEBPACK_IMPORTED_MODULE_5__.encodeClientNonce)(key) : undefined,
        universal: options.universal || false
      };
      websocketPool.watchTicket(ticket);
      // eslint-disable-next-line no-await-in-loop
      const result = await (0,_ui__WEBPACK_IMPORTED_MODULE_8__.QRCodeLogin)(options.qrcode, wwpassURLoptions, ttl * 900, options.qrcodeStyle, options.uiSwitch === 'auto' && isMobile() || options.uiSwitch === 'always');
      if (!result.refresh) return result;
    } catch (err) {
      if (!err.status) {
        options.log('QRCode auth error', err);
        // eslint-disable-next-line no-await-in-loop
        await (0,_ui__WEBPACK_IMPORTED_MODULE_8__.setRefersh)(options.qrcode, err);
        (0,_ui__WEBPACK_IMPORTED_MODULE_8__.clearQRCode)(options.qrcode, options.qrcodeStyle);
      } else {
        (0,_ui__WEBPACK_IMPORTED_MODULE_8__.clearQRCode)(options.qrcode, options.qrcodeStyle);
        if (err.status === _constants__WEBPACK_IMPORTED_MODULE_7__.WWPASS_STATUS.INTERNAL_ERROR || options.returnErrors) {
          return err;
        }
      }
      // eslint-disable-next-line no-await-in-loop
      await (0,_util__WEBPACK_IMPORTED_MODULE_2__.wait)(WAIT_ON_ERROR);
    }
  } while (document.documentElement.contains(options.qrcode));
  return {
    status: _constants__WEBPACK_IMPORTED_MODULE_7__.WWPASS_STATUS.TERMINAL_ERROR,
    reason: 'QRCode element is not in DOM'
  };
};
const qrCodeAndPasskeyAuth = options => {
  const websocketPool = new _wwpass_websocket__WEBPACK_IMPORTED_MODULE_1__["default"](options);
  const promises = [websocketPool.promise.then(result => {
    if (result.clientKey && options.catchClientKey) {
      options.catchClientKey(result.clientKey);
    }
    window.localStorage.setItem(METHOD_KEY_NAME, METHOD_QRCODE);
    return {
      ticket: result.ticket,
      callbackURL: options.callbackURL,
      ppx: options.ppx,
      version: _constants__WEBPACK_IMPORTED_MODULE_7__.PROTOCOL_VERSION
    };
  }).catch(err => {
    options.log(err);
    if (err.status) return err;
    return {
      status: _constants__WEBPACK_IMPORTED_MODULE_7__.WWPASS_STATUS.INTERNAL_ERROR,
      reason: err
    };
  }), qrCodeAuth(options, websocketPool)];
  if (options.passkeyButton) {
    promises.push((0,_passkey_auth__WEBPACK_IMPORTED_MODULE_0__.wwpassPasskeyAuth)(options));
  }
  return Promise.race(promises).finally(() => {
    websocketPool.close();
  });
};


/***/ },

/***/ "./node_modules/wwpass-frontend/src/mobile/gradient.svg.js"
/*!*****************************************************************!*\
  !*** ./node_modules/wwpass-frontend/src/mobile/gradient.svg.js ***!
  \*****************************************************************/
(__unused_webpack_module, __webpack_exports__, __webpack_require__) {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   "default": () => (__WEBPACK_DEFAULT_EXPORT__)
/* harmony export */ });
const qrCodeLogoSVG = '<defs><linearGradient id="a" x1="36" y1="50" x2="64" y2="50" gradientUnits="userSpaceOnUse"><stop offset="0" stop-color="#4200ff"/><stop offset="0.16" stop-color="#007fff"/><stop offset="0.27" stop-color="#00d1c5"/><stop offset="0.38" stop-color="#00ff29"/><stop offset="0.5" stop-color="#dbff00"/><stop offset="0.62" stop-color="#00ff29"/><stop offset="0.73" stop-color="#00d1c5"/><stop offset="0.84" stop-color="#007fff"/><stop offset="1" stop-color="#4200ff"/></linearGradient><linearGradient id="b" x1="32.75" x2="67.25" xlink:href="#a"/><linearGradient id="c" x1="28" x2="72" xlink:href="#a"/><linearGradient id="d" x1="23.25" x2="76.75" xlink:href="#a"/><linearGradient id="e" x1="18.5" x2="81.5" xlink:href="#a"/><linearGradient id="f" x1="15" y1="50" x2="85" y2="50" gradientUnits="userSpaceOnUse"><stop offset="0.05" stop-color="#007fff"/><stop offset="0.2" stop-color="#00d1c5"/><stop offset="0.34" stop-color="#00ff29"/><stop offset="0.5" stop-color="#dbff00"/><stop offset="0.66" stop-color="#00ff29"/><stop offset="0.8" stop-color="#00d1c5"/><stop offset="0.95" stop-color="#007fff"/></linearGradient></defs><path d="M100,0H0V100H100Z" fill="#fff"/><rect x="5.59" y="5.59" width="88.82" height="88.82" rx="4.61" fill="#000f2c"/><rect x="36" y="37.5" width="28" height="25" fill="url(#a)"/><path d="M65.83,65.83H67V67H65.83Zm0-17.59H64.66V47.07h1.17v1.17H67v2.35H65.83ZM63.48,62.31h1.18V60h1.17V58.79H64.66V55.27H63.48v3.52h1.18V60H63.48v1.18H62.31v3.51h1.17Zm-2.34-27h3.52v3.52H61.14Zm4.69-1.17H60V40h5.86ZM60,49.41h1.17v1.17H60ZM58.79,33H67v8.21H58.79Zm0,25.79H60V60H58.79Zm0-7H57.62v1.17h1.17Zm2.35,5.86H57.62v3.52h3.52Zm-3.52,4.69H56.45v1.17h1.17ZM56.45,34.17H55.28v1.17h1.17Zm4.69,16.41h1.17V47.07H61.14v1.17H60v1.17H58.79V48.24H56.45V47.07H55.28V45.9h1.17V42.38H55.28V41.21H54.1V40H52.93v1.18H51.76V37.69h1.17v1.17H54.1V37.69H52.93V36.52H51.76v1.17H50.59v3.52h1.17v1.17h1.17V41.21H54.1v3.51H52.93V45.9H51.76v1.17h1.17v2.34H54.1V48.24h2.35v1.17h1.17v1.18H60v1.17h1.17Zm-9.38,2.35H49.41V54.1h1.18v1.17h1.17Zm-1.17,7H49.41v1.17h1.18Zm-1.18-21.1H48.24v2.35h1.17ZM45.9,54.1H44.72v1.17H45.9ZM44.72,35.34H43.55V33h1.17v1.17H45.9V33h1.17v1.17H45.9v2.35H44.72Zm0,4.69H43.55v1.18h1.17Zm0,5.87H43.55v1.17h1.17Zm2.35,17.58h1.17V60H45.9v1.18h1.17v1.17H44.72v1.17H43.55v1.17h1.17v1.18h2.35Zm-4.69-27h1.17v1.17H42.38ZM41.21,48.83v-.59h1.17V47.07H41.21v1.17H40v1.17h1.18Zm8.2,8.79h2.35V56.45H49.41V55.27H48.24v1.18h1.17v1.17H47.07V56.45H45.9v1.17H44.72V56.45H43.55V55.27H42.38V54.1H41.21v1.17H40v1.18h1.18V55.27h1.17v1.18h1.17v1.17h1.17v1.17h4.69ZM35.35,35.34h3.51v3.52H35.35Zm0,25.8h3.51v3.51H35.35Zm4.68-27H34.17V40H40ZM40,60H34.17v5.87H40Zm3.52,5.87H42.38V63.48h1.17V60h1.17V58.79H42.38V57.62H37.69V56.45h1.17V55.27H36.52v2.35H35.35V56.45H33V55.27h2.35V52.93H34.17V54.1H33V51.76h2.35v1.17h1.17V54.1h1.17V52.93h1.17V54.1h2.35V52.93H40V51.76H36.52V50.59H40V49.41H36.52V48.24H35.35v1.17H33V45.9h1.17v1.17h7V45.9H40V44.72H37.69V45.9H36.52V44.72H34.17V42.38h2.35v2.34h1.17V43.55H40V42.38h1.18v1.17H40v1.17h1.18V45.9h1.17V43.55h1.17V42.38H42.38V38.86h2.34V40H45.9v1.18H44.72v1.17H45.9v7H43.55V48.24H42.38v1.17H41.21v1.18H40v1.17h1.18v1.17h1.17V54.1h2.34V52.93H43.55V51.76H42.38V50.59h2.34v2.34H45.9V50.59h1.17v2.34h1.17V49.41h1.17V48.24h1.18v1.17H49.41v1.18h1.18v1.17H54.1V50.59H52.93V49.41H51.76V47.07H50.59V45.9h1.17V44.72h1.17V43.55H51.76V42.38H50.59v2.34H49.41V43.55H48.24v1.17H47.07V43.55h1.17V42.38H47.07V38.86H45.9V37.69h1.17v1.17h1.17V34.17h1.17v2.35h2.35V35.34H50.59V33h2.34v1.17H51.76v1.17H54.1V34.17h1.18V33h2.34v3.52H55.28V35.34H54.1v2.35h1.18v3.52h1.17V40h1.17V45.9H60V44.72H58.79V42.38h2.35V45.9h2.34V44.72H62.31V42.38h1.17v2.34h1.18V43.55H67V45.9H65.83V44.72H64.66V45.9H63.48v3.51h1.18v1.18H63.48v1.17H61.14v1.17H60V54.1H57.62V52.93H56.45V51.76H55.28V54.1h1.17v1.17H60v1.18h2.34V55.27H61.14V54.1h1.17V52.93h1.17V54.1h1.18v1.17h1.17V52.93H64.66V51.76H67v3.51H65.83v2.35H67V60H65.83v3.52H67v1.17H63.48V67H60V65.83h2.34V64.65H60V62.31H58.79v2.34H57.62v1.18h1.17V67H56.45V63.48H55.28v2.35H54.1V64.65H52.93V60H54.1v3.52h1.18V60h1.17V57.62H55.28V56.45H54.1V55.27h1.18V54.1H54.1V52.93H52.93v4.69H54.1v1.17H51.76v2.35H50.59v2.34h1.17v1.17H50.59v1.18h2.34V67H50.59V65.83H49.41V64.65H48.24V67H43.55ZM33,33h8.21v8.21H33Zm0,25.79h8.21V67H33Z" fill="none" stroke-width="0.5" stroke="url(#b)"/><path d="M70.25,70.25h1.5v1.5h-1.5Zm0-22.5h-1.5v-1.5h1.5v1.5h1.5v3h-1.5Zm-3,18h1.5v-3h1.5v-1.5h-1.5v-4.5h-1.5v4.5h1.5v1.5h-1.5v1.5h-1.5v4.5h1.5Zm-3-34.5h4.5v4.5h-4.5Zm6-1.5h-7.5v7.5h7.5Zm-7.5,19.5h1.5v1.5h-1.5Zm-1.5-21h10.5v10.5H61.25Zm0,33h1.5v1.5h-1.5Zm0-9h-1.5v1.5h1.5Zm3,7.5h-4.5v4.5h4.5Zm-4.5,6h-1.5v1.5h1.5Zm-1.5-36h-1.5v1.5h1.5Zm6,21h1.5v-4.5h-1.5v1.5h-1.5v1.5h-1.5v-1.5h-3v-1.5h-1.5v-1.5h1.5v-4.5h-1.5v-1.5h-1.5v-1.5h-1.5v1.5h-1.5v-4.5h1.5v1.5h1.5v-1.5h-1.5v-1.5h-1.5v1.5h-1.5v4.5h1.5v1.5h1.5v-1.5h1.5v4.5h-1.5v1.5h-1.5v1.5h1.5v3h1.5v-1.5h3v1.5h1.5v1.5h3v1.5h1.5Zm-12,3h-3v1.5h1.5v1.5h1.5Zm-1.5,9h-1.5v1.5h1.5Zm-1.5-27h-1.5v3h1.5Zm-4.5,19.5h-1.5v1.5h1.5Zm-1.5-24h-1.5v-3h1.5v1.5h1.5v-1.5h1.5v1.5h-1.5v3h-1.5Zm0,6h-1.5v1.5h1.5Zm0,7.5h-1.5v1.5h1.5Zm3,22.5h1.5v-4.5h-3v1.5h1.5v1.5h-3v1.5h-1.5v1.5h1.5v1.5h3Zm-6-34.5h1.5v1.5h-1.5ZM38.75,48.5v-.75h1.5v-1.5h-1.5v1.5h-1.5v1.5h1.5Zm10.5,11.25h3v-1.5h-3v-1.5h-1.5v1.5h1.5v1.5h-3v-1.5h-1.5v1.5h-1.5v-1.5h-1.5v-1.5h-1.5v-1.5h-1.5v1.5h-1.5v1.5h1.5v-1.5h1.5v1.5h1.5v1.5h1.5v1.5h6Zm-18-28.5h4.5v4.5h-4.5Zm0,33h4.5v4.5h-4.5Zm6-34.5h-7.5v7.5h7.5Zm0,33h-7.5v7.5h7.5Zm4.5,7.5h-1.5v-3h1.5v-4.5h1.5v-1.5h-3v-1.5h-6v-1.5h1.5v-1.5h-3v3h-1.5v-1.5h-3v-1.5h3v-3h-1.5v1.5h-1.5v-3h3v1.5h1.5v1.5h1.5v-1.5h1.5v1.5h3v-1.5h-1.5v-1.5h-4.5v-1.5h4.5v-1.5h-4.5v-1.5h-1.5v1.5h-3v-4.5h1.5v1.5h9v-1.5h-1.5v-1.5h-3v1.5h-1.5v-1.5h-3v-3h3v3h1.5v-1.5h3v-1.5h1.5v1.5h-1.5v1.5h1.5v1.5h1.5v-3h1.5v-1.5h-1.5v-4.5h3v1.5h1.5v1.5h-1.5v1.5h1.5v9h-3v-1.5h-1.5v1.5h-1.5v1.5h-1.5v1.5h1.5v1.5h1.5v1.5h3v-1.5h-1.5v-1.5h-1.5v-1.5h3v3h1.5v-3h1.5v3h1.5v-4.5h1.5v-1.5h1.5v1.5h-1.5v1.5h1.5v1.5h4.5v-1.5h-1.5v-1.5h-1.5v-3h-1.5v-1.5h1.5v-1.5h1.5v-1.5h-1.5v-1.5h-1.5v3h-1.5v-1.5h-1.5v1.5h-1.5v-1.5h1.5v-1.5h-1.5v-4.5h-1.5v-1.5h1.5v1.5h1.5v-6h1.5v3h3v-1.5h-1.5v-3h3v1.5h-1.5v1.5h3v-1.5h1.5v-1.5h3v4.5h-3v-1.5h-1.5v3h1.5v4.5h1.5v-1.5h1.5v7.5h3v-1.5h-1.5v-3h3v4.5h3v-1.5h-1.5v-3h1.5v3h1.5v-1.5h3v3h-1.5v-1.5h-1.5v1.5h-1.5v4.5h1.5v1.5h-1.5v1.5h-3v1.5h-1.5v1.5h-3v-1.5h-1.5v-1.5h-1.5v3h1.5v1.5h4.5v1.5h3v-1.5h-1.5v-1.5h1.5v-1.5h1.5v1.5h1.5v1.5h1.5v-3h-1.5v-1.5h3v4.5h-1.5v3h1.5v3h-1.5v4.5h1.5v1.5h-4.5v3h-4.5v-1.5h3v-1.5h-3v-3h-1.5v3h-1.5v1.5h1.5v1.5h-3v-4.5h-1.5v3h-1.5v-1.5h-1.5v-6h1.5v4.5h1.5v-4.5h1.5v-3h-1.5v-1.5h-1.5v-1.5h1.5v-1.5h-1.5v-1.5h-1.5v6h1.5v1.5h-3v3h-1.5v3h1.5v1.5h-1.5v1.5h3v1.5h-3v-1.5h-1.5v-1.5h-1.5v3h-6Zm-13.5-42h10.5v10.5H28.25Zm0,33h10.5v10.5H28.25Z" fill="none" stroke-width="0.5" stroke="url(#c)"/><path d="M74.67,74.67H76.5V76.5H74.67Zm0-27.41H72.84V45.43h1.83v1.83H76.5v3.65H74.67ZM71,69.19h1.82V65.53h1.83V63.7H72.84V58.22H71V63.7h1.82v1.83H71v1.83H69.19v5.48H71Zm-3.66-42h5.48v5.48H67.36Zm7.31-1.83H65.53v9.13h9.14ZM65.53,49.08h1.83v1.83H65.53ZM63.71,23.5H76.5V36.29H63.71Zm0,40.2h1.82v1.83H63.71Zm0-11H61.88v1.83h1.83Zm3.65,9.14H61.88v5.48h5.48Zm-5.48,7.31H60.05V71h1.83ZM60.05,25.32H58.22v1.84h1.83Zm7.31,25.59h1.83V45.43H67.36v1.83H65.53v1.83H63.71V47.26H60.05V45.43H58.22V43.6h1.83V38.12H58.22V36.29H56.4V34.46H54.57v1.83H52.74V30.81h1.83v1.83H56.4V30.81H54.57V29H52.74v1.83H50.91v5.48h1.83v1.83h1.83V36.29H56.4v5.48H54.57V43.6H52.74v1.83h1.83v3.66H56.4V47.26h3.65v1.83h1.83v1.82h3.65v1.83h1.83ZM52.74,54.57H49.09v1.82h1.82v1.83h1.83Zm-1.83,11H49.09v1.83h1.82ZM49.09,32.64H47.26v3.65h1.83ZM43.6,56.39H41.78v1.83H43.6ZM41.78,27.16H40V23.5h1.83v1.83H43.6V23.5h1.83v1.83H43.6V29H41.78Zm0,7.3H40v1.83h1.83Zm0,9.14H40v1.83h1.83ZM45.43,71h1.83V65.53H43.6v1.83h1.83v1.83H41.78V71H40v1.83h1.83v1.83h3.65ZM38.12,29H40v1.83H38.12ZM36.29,48.17v-.91h1.83V45.43H36.29v1.83H34.47v1.83h1.82Zm12.8,13.71h3.65V60.05H49.09V58.22H47.26v1.83h1.83v1.83H45.43V60.05H43.6v1.83H41.78V60.05H40V58.22H38.12V56.39H36.29v1.83H34.47v1.83h1.82V58.22h1.83v1.83H40v1.83h1.83V63.7h7.31ZM27.16,27.16h5.48v5.48H27.16Zm0,40.2h5.48v5.48H27.16Zm7.31-42H25.33v9.13h9.14Zm0,40.2H25.33v9.14h9.14ZM40,74.67H38.12V71H40V65.53h1.83V63.7H38.12V61.88H30.81V60.05h1.83V58.22H29v3.66H27.16V60.05H23.5V58.22h3.66V54.57H25.33v1.82H23.5V52.74h3.66v1.83H29v1.82h1.83V54.57h1.83v1.82h3.65V54.57H34.47V52.74H29V50.91h5.49V49.09H29V47.26H27.16v1.83H23.5V43.6h1.83v1.83h11V43.6H34.47V41.77H30.81V43.6H29V41.77H25.33V38.12H29v3.65h1.83V40h3.66V38.12h1.82V40H34.47v1.82h1.82V43.6h1.83V40H40V38.12H38.12V32.64h3.66v1.82H43.6v1.83H41.78v1.83H43.6v11H40V47.26H38.12v1.83H36.29v1.82H34.47v1.83h1.82v1.83h1.83v1.82h3.66V54.57H40V52.74H38.12V50.91h3.66v3.66H43.6V50.91h1.83v3.66h1.83V49.09h1.83V47.26h1.82v1.83H49.09v1.82h1.82v1.83H56.4V50.91H54.57V49.09H52.74V45.43H50.91V43.6h1.83V41.77h1.83V40H52.74V38.12H50.91v3.65H49.09V40H47.26v1.82H45.43V40h1.83V38.12H45.43V32.64H43.6V30.81h1.83v1.83h1.83V25.33h1.83V29h3.65V27.16H50.91V23.5h3.66v1.83H52.74v1.83H56.4V25.33h1.82V23.5h3.66V29H58.22V27.16H56.4v3.65h1.82v5.48h1.83V34.46h1.83V43.6h3.65V41.77H63.71V38.12h3.65V43.6H71V41.77H69.19V38.12H71v3.65h1.82V40H76.5V43.6H74.67V41.77H72.84V43.6H71v5.49h1.82v1.82H71v1.83H67.36v1.83H65.53v1.82H61.88V54.57H60.05V52.74H58.22v3.65h1.83v1.83h5.48v1.83h3.66V58.22H67.36V56.39h1.83V54.57H71v1.82h1.82v1.83h1.83V54.57H72.84V52.74H76.5v5.48H74.67v3.66H76.5v3.65H74.67V71H76.5v1.83H71V76.5H65.53V74.67h3.66V72.84H65.53V69.19H63.71v3.65H61.88v1.83h1.83V76.5H60.05V71H58.22v3.66H56.4V72.84H54.57V65.53H56.4V71h1.82V65.53h1.83V61.88H58.22V60.05H56.4V58.22h1.82V56.39H56.4V54.57H54.57v7.31H56.4V63.7H52.74v3.66H50.91V71h1.83v1.83H50.91v1.83h3.66V76.5H50.91V74.67H49.09V72.84H47.26V76.5H40ZM23.5,23.5H36.29V36.29H23.5Zm0,40.21H36.29V76.5H23.5Z" fill="none" stroke-width="0.5" stroke="url(#d)"/><path d="M79.09,79.09h2.16v2.16H79.09Zm0-32.32H76.94V44.61h2.15v2.16h2.16v4.31H79.09ZM74.78,72.63h2.16V68.32h2.15V66.16H76.94V59.7H74.78v6.46h2.16v2.16H74.78v2.15H72.63v6.47h2.15ZM70.47,23.06h6.47v6.47H70.47Zm8.62-2.15H68.32V31.68H79.09Zm-10.77,28h2.15v2.15H68.32ZM66.16,18.75H81.25V33.84H66.16Zm0,47.41h2.16v2.16H66.16Zm0-12.93H64v2.16h2.15ZM70.47,64H64v6.46h6.46ZM64,72.63H61.85v2.15H64ZM61.85,20.9H59.7v2.16h2.15Zm8.62,30.17h2.16V44.61H70.47v2.16H68.32v2.15H66.16V46.77H61.85V44.61H59.7V42.46h2.15V36H59.7V33.84H57.54V31.68H55.39v2.16H53.23V27.37h2.16v2.16h2.15V27.37H55.39V25.22H53.23v2.15H51.08v6.47h2.15V36h2.16V33.84h2.15V40.3H55.39v2.16H53.23v2.15h2.16v4.31h2.15V46.77h4.31v2.15H64v2.16h4.31v2.15h2.15ZM53.23,55.39H48.92v2.15h2.16V59.7h2.15ZM51.08,68.31H48.92v2.16h2.16ZM48.92,29.53H46.77v4.31h2.15Zm-6.46,28H40.3v2.15h2.16ZM40.3,23.06H38.15V18.75H40.3v2.16h2.16V18.75h2.15v2.16H42.46v4.31H40.3Zm0,8.62H38.15v2.16H40.3Zm0,10.78H38.15v2.15H40.3Zm4.31,32.32h2.16V68.32H42.46v2.15h2.15v2.16H40.3v2.15H38.15v2.16H40.3v2.15h4.31ZM36,25.22h2.16v2.15H36ZM33.84,47.84V46.77H36V44.61H33.84v2.16H31.68v2.15h2.16ZM48.92,64h4.31V61.85H48.92V59.7H46.77v2.15h2.15V64H44.61V61.85H42.46V64H40.3V61.85H38.15V59.7H36V57.54H33.84V59.7H31.68v2.15h2.16V59.7H36v2.15h2.16V64H40.3v2.15h8.62ZM23.06,23.06h6.47v6.47H23.06Zm0,47.41h6.47v6.47H23.06Zm8.62-49.56H20.91V31.68H31.68Zm0,47.41H20.91V79.09H31.68Zm6.47,10.77H36V74.78h2.16V68.32H40.3V66.16H36V64H27.37V61.85h2.16V59.7H25.22V64H23.06V61.85H18.75V59.7h4.31V55.39H20.91v2.15H18.75V53.23h4.31v2.16h2.16v2.15h2.15V55.39h2.16v2.15h4.31V55.39H31.68V53.23H25.22V51.08h6.46V48.92H25.22V46.77H23.06v2.15H18.75V42.46h2.16v2.15H33.84V42.46H31.68V40.3H27.37v2.16H25.22V40.3H20.91V36h4.31V40.3h2.15V38.15h4.31V36h2.16v2.16H31.68V40.3h2.16v2.16H36V38.15h2.16V36H36V29.53H40.3v2.15h2.16v2.16H40.3V36h2.16V48.92H38.15V46.77H36v2.15H33.84v2.16H31.68v2.15h2.16v2.16H36v2.15H40.3V55.39H38.15V53.23H36V51.08H40.3v4.31h2.16V51.08h2.15v4.31h2.16V48.92h2.15V46.77h2.16v2.15H48.92v2.16h2.16v2.15h6.46V51.08H55.39V48.92H53.23V44.61H51.08V42.46h2.15V40.3h2.16V38.15H53.23V36H51.08V40.3H48.92V38.15H46.77V40.3H44.61V38.15h2.16V36H44.61V29.53H42.46V27.37h2.15v2.16h2.16V20.91h2.15v4.31h4.31V23.06H51.08V18.75h4.31v2.16H53.23v2.15h4.31V20.91H59.7V18.75H64v6.47H59.7V23.06H57.54v4.31H59.7v6.47h2.15V31.68H64V42.46h4.31V40.3H66.16V36h4.31v6.47h4.31V40.3H72.63V36h2.15V40.3h2.16V38.15h4.31v4.31H79.09V40.3H76.94v2.16H74.78v6.46h2.16v2.16H74.78v2.15H70.47v2.16H68.32v2.15H64V55.39H61.85V53.23H59.7v4.31h2.15V59.7h6.47v2.15h4.31V59.7H70.47V57.54h2.16V55.39h2.15v2.15h2.16V59.7h2.15V55.39H76.94V53.23h4.31V59.7H79.09V64h2.16v4.31H79.09v6.46h2.16v2.16H74.78v4.31H68.32V79.09h4.31V76.94H68.32V72.63H66.16v4.31H64v2.15h2.15v2.16H61.85V74.78H59.7v4.31H57.54V76.94H55.39V68.32h2.15v6.46H59.7V68.32h2.15V64H59.7V61.85H57.54V59.7H59.7V57.54H57.54V55.39H55.39V64h2.15v2.15H53.23v4.31H51.08v4.31h2.15v2.16H51.08v2.15h4.31v2.16H51.08V79.09H48.92V76.94H46.77v4.31H38.15ZM18.75,18.75H33.84V33.84H18.75Zm0,47.41H33.84V81.25H18.75Z" fill="none" stroke-width="0.5" stroke="url(#e)"/><path d="M84,16V30.9H69.1V16H84M69.52,30.48H83.59V16.41H69.52V30.48M64.69,16v5.24H61.86v-.41h2.42V16.41H61.86V16h2.83M55,16v.41H52.62v2.42h-.41V16H55M43,16v.41h-.42V16H43m-4.83,0v2.41h2.41v2.83h-.41V18.83H37.72V16h.42M30.9,16V30.9H16V16H30.9M16.41,30.48H30.48V16.41H16.41V30.48M59.86,18.41v.42h-.41v-.42h.41m-12.07,0v4.83h4.83v.42H50.21V32.9h2.41v.41H50.21v4.83h-.42V35.72H47.38V33.31H45V28.07h.41V32.9h4.41V26.07H47.38V18.41h.41m31.38,2.42v5.24H73.93V20.83h5.24m-21.72,0v2.83H57V21.24H54.62v-.41h2.83m-31.38,0v5.24H20.83V20.83h5.24m9.65,2.41v.42h-.41v-.42h.41m24.14,2.42V30.9h-.41V28.48H55V30.9h-.41V25.66H55v2.41h4.42V25.66h.41M43,25.66v.41h-.42v-.41H43m-4.83,2.41v.41H35.72V32.9h2.42v2.41h2.41V47.79H37.72V45.38H35.31V43H32.9v-.41h2.41V37.72h2.41V33.31H35.31V28.07h2.83M35.72,45h4.42V40.55H35.72V45m29-14.48V42.55h6.83V38.14H69.1V35.31h2.83v7.24h4.83v7.24h2.41v.41H76.76v2.42H73.93V52.2h2.41V43H71.93v2.42H69.52v2.41H69.1V45.38H64.28V43H61.86v-.41h2.42V33.31H61.86V32.9h2.42V30.48h.41m-24.14,0v.42h-.41v-.42h.41m16.9,2.42v5.24H57V35.72H54.62v-.41H57V32.9h.42m19.31,2.41v2.83h-.42V35.31h.42m-45.86,0v.41h-.42v-.41h.42m-9.66,0v2.83H18.41V35.31h2.83M84,37.72v2.83h-.41V38.14H81.17v-.42H84m-38.62,0v.42H45v-.42h.41m-16.9,0v.42H25.66v-.42h2.82m50.69,2.42v.41h-.41v-.41h.41M55,40.14v.41h-.41v-.41H55m-24.13,0v.41h-.42v-.41h.42m-7.24,0v.41h-.42v-.41h.42m29,2.41V43h-.41v-.41h.41m-36.21,0V45H30.9v.42H28.48v2.41H23.24V45.38H18.83v2.41H16V42.55h.41M81.59,45v.42h-.42V45h.42M55,45v2.83h-.41V45H55m29,2.42V50.2h-.41V47.38H84m-21.72,0v2.41h2.41V52.2h4.83v2.42h2.41V55H69.52v2.42H66.69V57H69.1V52.62H64.69V55h-.41V52.62H59.86v4.83h-.41V55H55V66.69h2.42v.41H52.62v4.83h-.41V69.51H47.79v4.41h2.42v4.83h2.41v.42H50.21v2.41h-.42V79.17H45.38V84H37.72V81.58H35.31V78.75h.41v2.42h2.42v2.41H45V78.75h2.41V69.51H40.55v4.42H43v.41H38.14v2.41h-.42V71.51h2.42V69.1h9.65V66.69h4.83V62.27H49.79V59.86H45.38v4.41h2.41v.42H45V62.27H40.55v2.42h-.41V62.27H37.72V59.86H35.31v-.41h2.83v2.41h4.41V57.44H40.14V57h2.41V52.2H43V57h4.41V49.79h.41V52.2h2.42v2.42h9.24V50.2H57v-.41h2.42V47.38h2.83M47.79,59.45h2.42v2.41h4.41V55H47.79v4.42m2.42-12.07v.41h-.42v-.41h.42m-16.9,0v.41H32.9v-.41h.41m38.62,2.41v.41h-.41v-.41h.41m-41,0v.41h-.42v-.41h.42m7.24,2.41V55h-.42V52.62H35.31V52.2h2.83m-9.66,0v.42H23.24V52.2h5.24M84,54.62v5.24h-.41V55H81.17v-.41H84m-53.1,0V55h-.42v-.41h.42m-12.07,0V55H16.41v2.42H16V54.62h2.83M76.76,57v2.42h2.41v.41H76.76V69.1h2.41v.41H76.76v2.42H74.34v7.24H71.52V74.34H67.1v4.83H64.69v4.41H67.1V84H64.28V78.75h2.41V74.34H62.28v2.41h-.42V71.51h2.42V64.69H61.86V62.27H59.45v-.41h2.41V59.45h.42v2.41h7.24v2.41h6.82V59.86H73.93v-.41h2.41V57h.42M64.69,73.93h9.24V64.69H64.69v9.24M33.31,57v.42H32.9V57h.41m-7.24,0v2.42H30.9v.41H28.48v4.41H32.9V61.86h.41v2.41h2.41v2.42h2.42v.41H35.31V64.69H25.66v-.42h2.41V59.86H21.24v4.83h-.41V62.27H16v-.41h4.83V57h.41v2.42h4.42V57h.41m55.52,4.83v4.83H84v2.82h-.41V67.1H81.17V61.86h.42M69.52,69.1v.41H69.1V69.1h.42m-38.62,0V84H16V69.1H30.9M16.41,83.58H30.48V69.51H16.41V83.58M81.59,71.51v7.24H84v.42H78.76V76.34h2.41V71.51h.42m-24.14,0v7.24h2.41v2.83h-.41V79.17H57V71.51h.42M26.07,73.93v5.24H20.83V73.93h5.24m50.69,7.24V84H71.52v-.42h4.82V81.17h.42M84,83.58V84h-.41v-.42H84m-29,0V84H52.21v-.42H55M85,15H68.1V31.9H85V15ZM70.52,29.48V17.41H82.59V29.48ZM65.69,15H60.86v2.41H58.45v2.42H53.62V17.41H56V15H51.21v4.83h2.41v2.41H48.79V17.41H46.38v9.66H44V24.66H41.55v2.41H44v7.24h2.41v2.41H44v2.42h2.41V36.72h2.41v2.42h2.42V34.31h2.41v2.41H56v2.42H53.62v2.41H51.21V44h2.41v4.83H56V51.2h2.42v2.42H51.21V51.2H48.79V48.79h2.42V46.38H48.79v2.41H46.38V56H44V51.2H41.55V56H39.14V51.2H34.31v2.42h2.41V56h2.42v2.42H34.31v2.41h2.41v2.41h2.42v2.42h2.41V63.27H44v2.42h4.82V63.27H46.38V60.86h2.41v2.41h4.83v2.42H48.79V68.1H39.14V65.69H36.72V63.27H34.31V60.86H31.9v2.41H29.48V60.86H31.9V58.45h2.41V56H31.9V53.62H29.48V51.2H31.9V48.79h2.41V46.38h2.41v2.41h4.83V34.31H39.14V31.9h2.41V29.48H39.14V31.9H36.72V29.48h2.42V27.07H34.31v7.24h2.41v2.41H34.31v4.83H31.9V39.14H29.48V36.72H31.9V34.31H29.48v2.41H24.66v2.42H22.24V34.31H17.41v4.83h4.83v2.41h2.42V39.14h4.82v2.41H31.9V44H17.41V41.55H15v7.24h4.83V46.38h2.41v2.41h7.24V51.2H22.24v2.42h7.24V56H31.9v2.42H27.07V56H24.66v2.42H22.24V56H19.83V53.62H15v4.83h2.41V56h2.42v4.83H15v2.41h4.83v2.42h2.41V60.86h4.83v2.41H24.66v2.42h9.65V68.1h4.83v2.41H36.72v7.24H34.31v4.83h2.41V85h9.66V80.17h2.41v2.41h2.42V80.17h2.41V77.75H51.21V72.93h2.41V68.1h4.83V65.69H56V56h2.42v2.42h2.41V53.62h2.42V56h2.41v2.42h4.83V56h2.41V53.62h4.83V51.2h2.41V48.79H77.76V41.55h2.41V39.14h2.42v2.41H85V36.72H80.17v2.42H77.76V34.31H75.34v4.83h2.42v2.41H72.93V34.31H68.1v4.83h2.42v2.41H65.69V29.48H63.28V31.9H60.86v2.41h2.42v7.24H60.86V44h2.42v2.42H68.1v2.41h2.42V46.38h2.41V44h2.41V51.2H72.93v2.42H70.52V51.2H65.69V48.79H63.28V46.38H58.45v2.41H56V44H53.62V41.55H56V39.14h2.42V31.9H56v2.41H53.62V31.9H51.21V24.66h2.41V22.24H56v2.42h2.42V19.83h2.41v2.41h4.83V15Zm-4.83,4.83V17.41h2.42v2.42ZM46.38,31.9V27.07h2.41V31.9ZM36.72,44V41.55h2.42V44Zm-7.24,4.83V46.38H31.9V44h2.41v2.42H31.9v2.41ZM65.69,56V53.62H68.1V56Zm-16.9,2.42V56h4.83v4.83H51.21V58.45Zm-9.65,2.41V58.44h2.41v2.42Zm9.65,12.06V70.51h2.42v2.41Zm-7.24,0V70.51h4.83v7.24H44v4.83H39.14V80.17H36.72V77.75h2.42V75.34H44V72.93ZM44,15H41.55v2.41H39.14V15H36.72v4.83h2.42v2.41h2.41V17.41H44V15ZM31.9,15H15V31.9H31.9V15ZM17.41,29.48V17.41H29.48V29.48Zm62.76-9.65H72.93v7.24h7.24V19.83Zm-53.1,0H19.83v7.24h7.24V19.83Zm9.65,2.41H34.31v2.42h2.41V22.24Zm24.14,2.42H58.45v2.41H56V24.66H53.62V31.9H56V29.48h2.42V31.9h2.41V24.66ZM82.59,44H80.17v2.42h2.42V44ZM85,46.38H82.59V51.2H85V46.38ZM72.93,48.79H70.52V51.2h2.41V48.79ZM85,53.62H80.17V56h2.42v4.83H80.17V68.1h2.42v2.41H80.17v4.83H77.76v4.83H75.34V72.93h2.42V70.51h2.41V68.1H77.76V60.86h2.41V58.45H77.76V56H75.34v2.42H72.93v2.41h2.41v2.41H70.52V60.86H63.28V58.45H60.86v2.41H58.45v2.41h2.41v2.42h2.42v4.82H60.86v7.24H58.45V70.51H56v9.66h2.42v2.41h2.41V77.75h2.42V85H68.1V82.58H65.69V80.17H68.1V75.34h2.42v4.83h4.82v2.41H70.52V85h7.24V80.17H85V77.75H82.59V70.51H85V65.69H82.59V60.86H85V53.62ZM65.69,72.93V65.69h7.24v7.24Zm-2.41,4.82V75.34h2.41v2.41Zm7.24-9.65H68.1v2.41h2.42V68.1Zm-38.62,0H15V85H31.9V68.1ZM17.41,82.58V70.51H29.48V82.58Zm9.66-9.65H19.83v7.24h7.24V72.93ZM85,82.58H82.59V85H85V82.58Zm-29,0H51.21V85H56V82.58Z" fill="url(#f)"/>';
/* harmony default export */ const __WEBPACK_DEFAULT_EXPORT__ = (qrCodeLogoSVG);

/***/ },

/***/ "./node_modules/wwpass-frontend/src/mobile/renderQR.js"
/*!*************************************************************!*\
  !*** ./node_modules/wwpass-frontend/src/mobile/renderQR.js ***!
  \*************************************************************/
(__unused_webpack_module, __webpack_exports__, __webpack_require__) {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   insertInnerSvg: () => (/* binding */ insertInnerSvg),
/* harmony export */   renderQR: () => (/* binding */ renderQR)
/* harmony export */ });
/* harmony import */ var qrcode__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! qrcode */ "./node_modules/qrcode/lib/browser.js");
/* harmony import */ var _gradient_svg__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! ./gradient.svg */ "./node_modules/wwpass-frontend/src/mobile/gradient.svg.js");
/* harmony import */ var _small_gradient_svg__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(/*! ./small_gradient.svg */ "./node_modules/wwpass-frontend/src/mobile/small_gradient.svg.js");



function qrToElements(qr, size) {
  const height = 0.9;
  const dy = (1 - height) / 2;
  const rx = 0.5;
  function isSpecial(x, y) {
    // for a "pixel" of a QR-code, returns if it is in a reference squaire
    // (reference squaires are not rendered with our special round-cornered style)
    return x < 8 && y < 8 || x < 8 && y > size - 9 || x > size - 9 && y < 8;
  }
  function drawRefSquaire(x, y) {
    // creates elements of SVG for big reference squaire
    const path = `<path d="M ${x} ${y} h 7 v 7 h -7 Z M ${x + 1} ${y + 1} v 5 h 5 v -5 Z"/>`;
    const rect = `<rect x="${x + 2}" y="${y + 2}" width="3" height="3"/>`;
    return path + rect;
  }
  function drawRef() {
    // creates three big reference squaires in the corners of QR-code
    return drawRefSquaire(0, 0) + drawRefSquaire(0, size - 7) + drawRefSquaire(size - 7, 0);
  }
  function drawRect(x, y, length) {
    // creates one rounded-cornered rectangle as an element of QR-code
    return `<rect height="${height}" rx="${rx}" x="${x + dy}" y="${y + dy}" width="${length - 2 * dy}"/>`;
  }
  function drawRects() {
    // creates the main part of QR-code, made of round-cornered rectangles
    let i;
    let j;
    let paint;
    let startj;
    let res = '';
    for (i = 0; i < size; i += 1) {
      paint = false;
      startj = 0;
      for (j = 0; j <= size; j += 1) {
        const index = i * size + j;
        if (paint && (isSpecial(j, i) || j === size || qr[index] === 0)) {
          res += drawRect(startj, i, j - startj);
          paint = false;
        } else if (!paint && j < size && !isSpecial(j, i) && qr[index] === 1) {
          startj = j;
          paint = true;
        }
      }
    }
    return res;
  }
  return `${drawRects()}${drawRef()}`;
}
function renderQR(text, opts) {
  const qrData = qrcode__WEBPACK_IMPORTED_MODULE_0__.create(text, opts);
  const color = '#000F2C';
  const qrMargin = 4;
  const qrcodesize = qrData.modules.size + qrMargin * 2;
  const g = `<g fill="${color}"> ${qrToElements(qrData.modules.data, qrData.modules.size)} </g>`;
  const viewBox = `viewBox="${-qrMargin} ${-qrMargin} ${qrcodesize} ${qrcodesize}"`;
  const svgTag = `<svg xmlns="http://www.w3.org/2000/svg" ${viewBox} style="background-color:white"> ${g}
  </svg>`;
  return {
    svgTag,
    qrcodesize,
    qrMargin
  };
}
function createInnerSvg(isBig, innerOffset, innerSize) {
  let innerText;
  const viewBoxSize = 100;
  if (isBig) {
    innerText = _gradient_svg__WEBPACK_IMPORTED_MODULE_1__["default"];
  } else {
    innerText = _small_gradient_svg__WEBPACK_IMPORTED_MODULE_2__["default"];
  }
  const viewBox = `"0 0 ${viewBoxSize} ${viewBoxSize}"`;
  return `<svg x="${innerOffset}" y="${innerOffset}" width="${innerSize}" height="${innerSize}" viewBox=${viewBox}>
  ${innerText}
  </svg>`;
}
function insertInnerSvg(QRCodeElement, qrcodesize, qrMargin) {
  const outerSvg = QRCodeElement.getElementsByTagName('svg')[0];

  /* Size of inner logo SVG. 24% rounded to match odd number of untis
   * + 0.1 to cover the gap between units */
  const innerSize = Math.floor(qrcodesize * 0.12) * 2 + 1.1;
  // Center the inner logo
  const innerOffset = (qrcodesize - innerSize) / 2 - qrMargin;
  const clientInnerSize = outerSvg.clientHeight * (innerSize / qrcodesize);
  const isBig = clientInnerSize > 50;
  outerSvg.innerHTML += createInnerSvg(isBig, innerOffset, innerSize);
}

/***/ },

/***/ "./node_modules/wwpass-frontend/src/mobile/small_gradient.svg.js"
/*!***********************************************************************!*\
  !*** ./node_modules/wwpass-frontend/src/mobile/small_gradient.svg.js ***!
  \***********************************************************************/
(__unused_webpack_module, __webpack_exports__, __webpack_require__) {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   "default": () => (__WEBPACK_DEFAULT_EXPORT__)
/* harmony export */ });
const qrCodeLogoSVG = `<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" width="100" height="100" viewBox="0 0 100 100">
<defs>
  <linearGradient id="gra">
    <stop offset="0.05" stop-color="#007fff"/>
    <stop offset="0.2" stop-color="#00d1c5"/>
    <stop offset="0.34" stop-color="#00ff29"/>
    <stop offset="0.5" stop-color="#dbff00"/>
    <stop offset="0.66" stop-color="#00ff29"/>
    <stop offset="0.8" stop-color="#00d1c5"/>
    <stop offset="0.95" stop-color="#007fff"/>
  </linearGradient>
</defs>
<path d="M100,0H0V100H100Z" fill="#fff"/>
<rect x="9" y="9" width="82" height="82" rx="4" fill="url(#gra)" />
</svg>`;
/* harmony default export */ const __WEBPACK_DEFAULT_EXPORT__ = (qrCodeLogoSVG);

/***/ },

/***/ "./node_modules/wwpass-frontend/src/mobile/ui.js"
/*!*******************************************************!*\
  !*** ./node_modules/wwpass-frontend/src/mobile/ui.js ***!
  \*******************************************************/
(__unused_webpack_module, __webpack_exports__, __webpack_require__) {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   QRCodeLogin: () => (/* binding */ QRCodeLogin),
/* harmony export */   clearQRCode: () => (/* binding */ clearQRCode),
/* harmony export */   sameDeviceLogin: () => (/* binding */ sameDeviceLogin),
/* harmony export */   setRefersh: () => (/* binding */ setRefersh)
/* harmony export */ });
/* harmony import */ var _renderQR__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! ./renderQR */ "./node_modules/wwpass-frontend/src/mobile/renderQR.js");
/* harmony import */ var _urls__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! ../urls */ "./node_modules/wwpass-frontend/src/urls.js");
/* harmony import */ var _error__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(/*! ../error */ "./node_modules/wwpass-frontend/src/error.js");
/* harmony import */ var _constants__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(/*! ../constants */ "./node_modules/wwpass-frontend/src/constants.js");




const removeLoader = element => {
  while (element.firstChild) {
    element.removeChild(element.firstChild);
  }
};
let haveStyleSheet = false;
const setLoader = (element, styles) => {
  const loaderClass = `${styles.prefix || 'wwp_'}qrcode_loader`;
  const loader = document.createElement('div');
  loader.innerHTML = `<div style="width: 100%; height: 0; padding-block-end: 100%; position: relative;">
  <div class="${loaderClass}">
    <div class="${loaderClass}_blk"></div>
    <div class="${loaderClass}_blk ${loaderClass}_delay"></div>
    <div class="${loaderClass}_blk ${loaderClass}_delay"></div>
    <div class="${loaderClass}_blk"></div>
  </div>
</div>`;
  if (!haveStyleSheet) {
    const style = document.createElement('style');
    style.innerHTML = `@keyframes ${styles.prefix || 'wwp_'}pulse {
      0%   { opacity: 1; }
      100% { opacity: 0; }
    }
    .${loaderClass} {
      display: flex;
      flex-direction: row;
      flex-wrap: wrap;
      justify-content: space-around;
      align-items: center;
      width: 30%;
      height: 30%;
      margin-left: 35%;
      padding-top: 35%;
      position: absolute;
    }
    .${loaderClass}_blk {
      height: 35%;
      width: 35%;
      animation: ${styles.prefix || 'wwp_'}pulse 0.75s ease-in infinite alternate;
      background-color: #cccccc;
    }
    .${loaderClass}_delay {
      animation-delay: 0.75s;
    }`;
    document.getElementsByTagName('head')[0].appendChild(style);
    haveStyleSheet = true;
  }
  removeLoader(element);
  element.appendChild(loader);
};
const setRefersh = (element, error) => {
  const httpsRequired = error instanceof _error__WEBPACK_IMPORTED_MODULE_2__["default"] && error.code === _constants__WEBPACK_IMPORTED_MODULE_3__.WWPASS_STATUS.SSL_REQUIRED;
  const offline = window.navigator.onLine !== undefined && !window.navigator.onLine;
  const wrapper = document.createElement('div');
  wrapper.style.display = 'flex';
  wrapper.style.alignItems = 'center';
  wrapper.style.height = '100%';
  wrapper.style.width = '100%';
  const refreshNote = document.createElement('div');
  refreshNote.style.margin = '0 10%';
  refreshNote.style.width = '80%';
  refreshNote.style.textAlign = 'center';
  refreshNote.style.overflow = 'hidden';
  let text = 'Error occured';
  if (httpsRequired) {
    text = 'Please use HTTPS';
  } else if (offline) {
    text = 'No internet connection';
  }
  refreshNote.innerHTML = `<p style="margin:0; font-size: 1.2em; color: black;">${text}</p>`;
  let refreshButton = null;
  if (!httpsRequired) {
    refreshButton = document.createElement('a');
    refreshButton.textContent = 'Retry';
    refreshButton.style.fontWeight = '400';
    refreshButton.style.fontFamily = '"Arial", sans-serif';
    refreshButton.style.fontSize = '1.2em';
    refreshButton.style.lineHeight = '1.7em';
    refreshButton.style.cursor = 'pointer';
    refreshButton.href = '#';
    refreshNote.appendChild(refreshButton);
  }
  wrapper.appendChild(refreshNote);
  // eslint-disable-next-line no-console
  console.error(`Error in WWPass Library: ${error}`);
  removeLoader(element);
  element.appendChild(wrapper);
  return httpsRequired ? Promise.reject(error.message) : new Promise(resolve => {
    // Refresh after 1 minute or on click
    setTimeout(() => {
      resolve({
        refresh: true
      });
    }, 60000);
    refreshButton.addEventListener('click', event => {
      resolve({
        refresh: true
      });
      event.preventDefault();
    });
    if (offline) {
      window.addEventListener('online', () => resolve({
        refresh: true
      }));
    }
  });
};
const debouncePageVisibilityFactory = (state = 'visible') => {
  let debounce = null;
  return fn => {
    debounce = fn;
    const onDebounce = () => {
      if (document.visibilityState === state) {
        debounce();
        document.removeEventListener('visibilitychange', onDebounce);
      }
    };
    if (document.visibilityState === state) {
      debounce();
    } else {
      document.addEventListener('visibilitychange', onDebounce);
    }
  };
};
const debouncePageVisible = debouncePageVisibilityFactory();
const QRCodeLogin = (parentElement, wwpassURLoptions, ttl, qrcodeStyle, showSwitch) => new Promise(resolve => {
  const QRCodeElement = document.createElement('div');
  const {
    svgTag,
    qrcodesize,
    qrMargin
  } = (0,_renderQR__WEBPACK_IMPORTED_MODULE_0__.renderQR)((0,_urls__WEBPACK_IMPORTED_MODULE_1__.getUniversalURL)(wwpassURLoptions, true), qrcodeStyle || {});
  QRCodeElement.innerHTML = svgTag;
  const svgDiv = QRCodeElement;
  if (qrcodeStyle) {
    QRCodeElement.className = `${qrcodeStyle.prefix}qrcode_div`;
    QRCodeElement.style.max_width = `${qrcodeStyle.width}px`;
    QRCodeElement.style.max_height = `${qrcodeStyle.width}px`;
  }
  QRCodeElement.style.position = 'relative';
  QRCodeElement.style.width = '100%';
  let authElement = null;
  if (showSwitch) {
    const universalLinkElement = document.createElement('a');
    universalLinkElement.href = '#';
    universalLinkElement.addEventListener('click', e => {
      if (!universalLinkElement.href.endsWith('#')) return;
      resolve({
        away: true,
        linkElement: universalLinkElement
      });
      e.preventDefault();
    });
    universalLinkElement.appendChild(QRCodeElement);
    authElement = universalLinkElement;
  } else authElement = QRCodeElement;
  const qrCodeSwitchLink = document.createElement('a');
  qrCodeSwitchLink.href = '#';
  qrCodeSwitchLink.style.background = '#FFFFFF';
  qrCodeSwitchLink.style.color = '#000F2C';
  qrCodeSwitchLink.style.textAlign = 'center';
  qrCodeSwitchLink.style.padding = '.3em 0';
  qrCodeSwitchLink.style.width = '100%';
  qrCodeSwitchLink.style.display = 'inline-block';
  qrCodeSwitchLink.style.textDecorationLine = 'underline';
  qrCodeSwitchLink.style.cursor = 'pointer';
  qrCodeSwitchLink.innerText = 'or use WWPass Key on this device';
  qrCodeSwitchLink.id = 'wwp_switch_to_button';
  qrCodeSwitchLink.addEventListener('click', () => {
    resolve({
      button: true
    });
  });
  removeLoader(parentElement);
  parentElement.appendChild(authElement);
  if (showSwitch) {
    parentElement.appendChild(qrCodeSwitchLink);
  }
  (0,_renderQR__WEBPACK_IMPORTED_MODULE_0__.insertInnerSvg)(svgDiv, qrcodesize, qrMargin);
  if (ttl) {
    setTimeout(() => {
      debouncePageVisible(() => {
        resolve({
          refresh: true
        });
      });
    }, ttl);
  }
});
let haveButtonStyleSheet = false;
const addButtonStyleSheet = () => {
  if (!haveButtonStyleSheet) {
    const style = document.createElement('style');
    style.innerHTML = `
      @font-face {
        font-family: "Roboto";
        font-style: normal;
        font-weight: 300;
        src: local('Roboto Light'), local('Roboto-Light'), url('https://fonts.gstatic.com/s/roboto/v18/Hgo13k-tfSpn0qi1SFdUfVtXRa8TVwTICgirnJhmVJw.woff2') format('woff2');
        unicode-range: U+0000-00FF, U+0131, U+0152-0153, U+02C6, U+02DA, U+02DC, U+2000-206F, U+2074, U+20AC, U+2212, U+2215;
        font-display: swap;
      }

      .wwpassButtonContainer {
        min-width: 210px;
        /* margin: 20px 10px;
        display: flex; */
        justify-content: center;
      }

      .wwpassLoginButton {
        display: flex;


        height: 48px;

        background-color: #000F2C;
        background-image: url('data:image/svg+xml;utf8,<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" width="110" height="48" viewBox="0 0 110 48"><defs><style>.a{fill:url(%23a);}.b{fill:url(%23b);}.c{fill:url(%23c);}.d{fill:url(%23d);}.e{fill:url(%23e);}%3C%2Fstyle%3E<linearGradient id="a" x1="33.07" y1="53.98" x2="103.63" y2="13.24" gradientUnits="userSpaceOnUse"><stop offset="0" stop-color="%2300a3ff"/><stop offset="0.66" stop-color="%23007fff"/><stop offset="1" stop-color="%234200ff"/></linearGradient><linearGradient id="b" x1="31.75" y1="45.12" x2="109.11" y2="0.46" gradientUnits="userSpaceOnUse"><stop offset="0" stop-color="%2300ff29"/><stop offset="0.39" stop-color="%2300a3ff"/><stop offset="0.65" stop-color="%23007fff"/><stop offset="1" stop-color="%234200ff"/></linearGradient><linearGradient id="c" x1="21.24" y1="35.3" x2="61.59" y2="12" gradientUnits="userSpaceOnUse"><stop offset="0" stop-color="%2300ff29"/><stop offset="1" stop-color="%2300a3ff"/></linearGradient><linearGradient id="d" x1="26.02" y1="28.76" x2="58.35" y2="10.09" xlink:href="%23c"/><linearGradient id="e" x1="32.49" y1="47.89" x2="97.86" y2="10.15" gradientUnits="userSpaceOnUse"><stop offset="0" stop-color="%2300ff29"/><stop offset="0.36" stop-color="%2300a3ff"/><stop offset="0.61" stop-color="%23007fff"/><stop offset="1" stop-color="%234200ff"/></linearGradient></defs><polygon class="a" points="60 0 110 0 110 48 43 48 60 0"/><path class="b" d="M45.68,48h-.74l17-48h.9ZM60.8,0H60L42.91,48h.82ZM59.65,0h-.82L41.75,48h.83ZM58,0h-.71L40.21,48H41ZM55,0h-.82L37.13,48H38ZM76.85,0h-.7L59.08,48h.69ZM64,0h-.93l-17,48h.85Zm10.4,0h-.83L56.51,48h.82ZM72.23,0h-.7L54.46,48h.69Zm3.2,0h-.82L57.54,48h.82ZM71.07,0h-.69L53.3,48H54Zm-3,0h-.91l-17,48h.74Zm1.07,0h-.72L51.38,48h.8ZM66.45,0H65L47.91,48h1.47ZM53.87,0h-.82L36,48h.82ZM35,0h-.83L17.11,48h.83Zm2.05,0h-.82L19.16,48H20Zm1.13,0h-.9l-17,48H21Zm2.47,0H39.19L22.12,48h1.46ZM32.44,0h-.82L14.54,48h.83Zm1.41,0H33L16,48h.82ZM11.34,48h.82L29.23,0h-.82ZM44,0h-.82L26.09,48h.83Zm2.57,0h-.83L28.66,48h.83ZM42.22,0H41.5L24.43,48h.8Zm8.83,0h-.7L33.28,48H34ZM49.13,0H47.66L30.59,48h1.46Zm3.2,0h-.8l-17,48h.72ZM45.4,0h-.82L27.51,48h.82ZM57.08,0h-.82L39.18,48H40ZM110,3.2V1.15L93.31,48H94Zm0,3.25V4.39L94.47,48h.73ZM109.09,0h-1.38L90.62,48H92ZM110,12V10.15L96.52,48h.71ZM102.7,0H102L84.87,48h.81ZM78.13,0H77.3L60.23,48h.83Zm28.42,0h-1.4L88.08,48h1.45ZM110,29.87V26.2L102.27,48h1.27Zm0,9V36.81L106,48h.73Zm0,4.24v-2L107.56,48h.71Zm0-7.48V33.57L104.86,48h.73Zm0-14.41V17.36L99.09,48h1.37ZM100.87,0H100L83,48h.83ZM110,15.09V13.17L97.65,48h.63ZM104,0h-.85L86,48h.83ZM89.73,0H89L71.91,48h.81Zm-3.1,0h-.85L68.7,48h.83Zm2,0h-.86l-17,48h.83ZM85.47,0h-.85L67.55,48h.83ZM80.75,0h-1L62.67,48h1.06Zm3.18,0H83.1l-17,48h.73ZM82.16,0h-.75L64.34,48h.81ZM92.4,0h-.85L74.48,48h.83ZM97,0h-.85L79.1,48h.83Zm1.16,0h-.85L80.25,48h.83Zm-7,0H90.4L73.32,48h.81Zm3.72,0h-.65L77.07,48h.78Zm4.75,0h-.86l-17,48h.83ZM93.71,0h-.64L75.91,48h.79Z"/><path class="c" d="M16.13,48H15.6L32.67,0h.54ZM37,0h-.54L19.35,48h.53Zm2.83,0h-.62l-17,48h.54ZM39,0h-.62l-17,48h.45ZM34,0h-.54L16.35,48h.53Zm1.92,0h-.46L18.35,48h.53Zm-.59,0h-.53L17.68,48h.54Zm2.42,0h-.54L20.1,48h.53Zm3.66,0h-.95L23.35,48h.95Zm5.17,0H46L28.93,48h.54Zm.67,0h-.54L29.6,48h.53ZM45.12,0h-.45L27.6,48h.45ZM42.46,0h-.62l-17,48h.45Zm1.91,0h-.45L26.85,48h.45ZM43.13,0h-.46L25.6,48h.53ZM0,48H.54L17.61,0h-.54ZM22.29,0h-.53L4.68,48h.54ZM23,0h-.62l-17,48h.45ZM21,0h-.54L3.35,48h.53Zm3.66,0h-.95L6.6,48h1ZM20.21,0h-.54L2.6,48h.53Zm-.92,0h-.53L1.68,48h.54ZM48.12,0h-.45L30.6,48h.45ZM28.46,0h-.54L10.85,48h.53Zm1.66,0h-.95L12.1,48h1ZM25.63,0h-.46L8.1,48h.53Zm5.74,0h-.45L13.85,48h.45Zm.84,0h-.54l-17,48h.45ZM26.79,0h-.53L9.18,48h.54Zm.92,0h-.54L10.1,48h.53ZM74.56,0h-.89L56.57,48h.9ZM70.4,0h-.48L52.82,48h.48ZM69.06,0h-.89L51.07,48H52Zm2.09,0h-.48L53.57,48h.48ZM65.73,0h-.56L48.1,48h.53ZM64.9,0h-.48L47.35,48h.53ZM63.73,0h-.56L46.1,48h.53ZM67.4,0h-.89L49.43,48h1Zm5,0H72L54.91,48h.47Zm6.25,0h-.48L61.07,48h.48Zm.92,0h-.4L62.07,48h.48Zm2.08,0h-.48L64.07,48h.48Zm-8.5,0h-.48l-17,48h.39ZM49,0h-.54L31.35,48h.53Zm27.6,0h-.89l-17,48h.81ZM77.9,0h-.48L60.32,48h.48ZM54.48,0h-.56L36.85,48h.53Zm1.25,0h-.56l-17,48h.54Zm-2,0h-.56L36.1,48h.53ZM51.57,0h-.48L34,48h.54Zm-.92,0H50L32.93,48h.7Zm5.83,0H56L38.93,48h.54ZM52.73,0h-.56l-17,48h.45ZM62.9,0h-.56l-17,48h.53ZM61.23,0h-.56L43.6,48h.53ZM59.82,0h-.4L42.27,48h.53ZM62,0h-.56L44.35,48h.53ZM57.4,0h-.48L39.85,48h.53Zm.83,0h-.56L40.6,48h.53Zm.84,0h-.4L41.52,48h.53Z"/><path class="d" d="M22.5,48H21.35L38.43,0h1.14ZM35.57,0h-.64L17.85,48h.65Zm1.1,0H36L19,48h.65Zm7.5,0h-.64L26.45,48h.65Zm-10,0h-.55L16.55,48h.64Zm9.09,0h-.64L25.55,48h.65Zm-1.2,0h-.63l-17,48H25Zm-1,0h-.54L23.45,48H24ZM6.35,48H7L24.07,0h-.64ZM27.67,0H27L10,48h.65Zm-1.1,0h-.64L8.85,48H9.5Zm4.49,0h-.72l-17,48h.56ZM33,0H31.83L14.75,48H15.9Zm-2.8,0h-.64L12.45,48h.65Zm-1.6,0h-.64L10.85,48h.65Zm9,0h-.64L19.85,48h.65Zm20,0H57L40,48h.55Zm1.7,0h-.64L41.55,48h.65Zm-2.6,0h-.54L39.05,48h.55ZM55.18,0h-.55L37.55,48h.64ZM45.77,0h-.64L28.05,48h.65Zm15.4,0h-.54L43.55,48h.55Zm-1.1,0h-.64L42.35,48H43Zm2.1,0h-.64L44.45,48h.65ZM47.77,0h-.64L30.05,48h.65Zm6.59,0h-.72l-17,48h.56ZM46.48,0h-.55L28.85,48h.64Zm2.19,0H48L31,48h.65Zm4.4,0H51.93L34.85,48H36Zm-1.9,0h-.73l-17,48h.66Zm-.91,0h-.72l-17,48h.56Z"/><path class="e" d="M58.19,48h-.63L74.72,0h.49ZM74.31,0h-.49L56.66,48h.63Zm-1,0h-.67L55.55,48h.65Zm4.49,0h-.66L60.05,48h.65ZM76.9,0h-.67L59.15,48h.65Zm2,0h-.67l-17,48h.65Zm-11,0h-.67L50.15,48h.65ZM46.35,48h.84l17-48h-.78ZM71.21,0h-.58L53.55,48h.64Zm-5.9,0h-.58L47.65,48h.64ZM66.7,0H66L49,48h.56Zm3.61,0h-.67l-17,48h.65ZM68.8,0h-.67L51.05,48h.65ZM79.9,0h-.67L62.15,48h.65ZM72.31,0h-.58L54.65,48h.64Zm9,0h-.58L63.65,48h.64ZM92.9,0H91.82L74.73,48H75.8Zm4,0h-.58L79.23,48h.57Zm.9,0h-.58L80.13,48h.57ZM91.2,0h-.57l-17,48h.48Zm10.2,0h-.58L83.73,48h.57ZM98.91,0h-.49L81.33,48h.56ZM95.3,0H94.23l-17,48h1Zm-11,0H83.23L66.15,48h1.14Zm6,0h-.49L72.73,48h.56Zm-4,0H85.22L68.13,48H69.2Zm-4,0h-.66L64.55,48h.65ZM88.8,0h-.58L71.13,48h.57Zm-.9,0h-.58L70.23,48h.57Z"/></svg>');
        background-position: 190px;
        background-repeat: no-repeat;

        font-size: 18px;
        line-height: 48px;
        font-family: Roboto, Arial, Helvetica, sans-serif;

        padding-left: 24px;
        border: none;
        color: #FFFFFF;

        text-decoration: none;
    }

    .wwpassLoginButton:hover, .wwpassLoginButton:focus  {
        opacity: .9;
        color: #FFFFFF;
    }

    .wwpassQRButton {
      margin-top: 24px;
      display: flex;
      height: 48px;

      background-color: #000F2C;
      background-image: url('data:image/svg+xml;utf8,<svg width="32" height="32" viewBox="0 0 32 32" fill="none" xmlns="http://www.w3.org/2000/svg"><path d="M14 17V25H18" stroke="white" stroke-width="2"/><rect x="3" y="22" width="7" height="7" stroke="white" stroke-width="2"/><rect x="3" y="3" width="7" height="7" stroke="white" stroke-width="2"/><rect x="22" y="3" width="7" height="7" stroke="white" stroke-width="2"/><path d="M19 7H14V14H10V18H2" stroke="white" stroke-width="2"/><path d="M2 14H7" stroke="white" stroke-width="2"/><path d="M29 17V25H25V18H18V10" stroke="white" stroke-width="2"/><path d="M13 3H19" stroke="white" stroke-width="2"/><path d="M13 29H18" stroke="white" stroke-width="2"/><path d="M24 29H30" stroke="white" stroke-width="2"/><path d="M21 14H30" stroke="white" stroke-width="2"/><path d="M21 30V22H17" stroke="white" stroke-width="2"/></svg>');
      background-position: right 8px top 8px;
      background-repeat: no-repeat;

      font-size: 18px;
      line-height: 48px;
      font-family: Roboto, Arial, Helvetica, sans-serif;

      padding-left:24px;
      border: none;
      color: #FFFFFF;
      text-decoration: none;
    }

    .wwpassQRButton:hover,
    .wwpassQRButton:focus {
      opacity: .9;
    }

    .wwpassQRButton:active {
      opacity: .7;
    }`;
    document.getElementsByTagName('head')[0].appendChild(style);
    haveButtonStyleSheet = true;
  }
};
const sameDeviceLogin = (options, wwpassURLoptions, ttl, showSwitch = true) => new Promise(resolve => {
  const parentElement = options.qrcode;
  addButtonStyleSheet();
  const universalLinkElement = document.createElement('a');
  universalLinkElement.className = 'wwpassLoginButton';
  universalLinkElement.classList.add('wwpass-frontend-custom');
  universalLinkElement.innerText = wwpassURLoptions && wwpassURLoptions.buttonText || 'Log in with WWPass';
  if (wwpassURLoptions) {
    universalLinkElement.href = (0,_urls__WEBPACK_IMPORTED_MODULE_1__.getUniversalURL)(wwpassURLoptions, false);
  } else universalLinkElement.href = '#';
  const qrCodeSwitchLink = document.createElement('a');
  if (showSwitch) {
    qrCodeSwitchLink.href = '#';
    qrCodeSwitchLink.className = 'wwpassQRButton';
    qrCodeSwitchLink.classList.add('wwpass-frontend-custom');
    qrCodeSwitchLink.innerText = 'Show QR code';
    qrCodeSwitchLink.addEventListener('click', e => {
      resolve({
        qrcode: true
      });
      e.preventDefault();
    });
  }
  universalLinkElement.addEventListener('click', e => {
    if (!universalLinkElement.href.endsWith('#')) return;
    resolve({
      away: true,
      linkElement: universalLinkElement
    });
    e.preventDefault();
  });
  if (options.mobileLoginExtraButtons && options.mobileLoginExtraButtons.length) {
    for (let i = 0; i < options.mobileLoginExtraButtons.length; i += 1) {
      options.mobileLoginExtraButtons[i].addEventListener('click', e => {
        resolve({
          away: true,
          linkElement: universalLinkElement
        });
        e.preventDefault();
      });
    }
  }
  const buttonContainer = document.createElement('div');
  buttonContainer.appendChild(universalLinkElement);
  if (showSwitch) {
    buttonContainer.appendChild(qrCodeSwitchLink);
  }
  buttonContainer.className = 'wwpassButtonContainer';
  removeLoader(parentElement);
  parentElement.appendChild(buttonContainer);
  if (ttl) {
    setTimeout(() => {
      debouncePageVisible(() => {
        resolve({
          refresh: true
        });
      });
    }, ttl);
  }
});
const clearQRCode = (parentElement, style) => setLoader(parentElement, style);


/***/ },

/***/ "./node_modules/wwpass-frontend/src/mobile/wwpass.websocket.js"
/*!*********************************************************************!*\
  !*** ./node_modules/wwpass-frontend/src/mobile/wwpass.websocket.js ***!
  \*********************************************************************/
(__unused_webpack_module, __webpack_exports__, __webpack_require__) {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   "default": () => (__WEBPACK_DEFAULT_EXPORT__)
/* harmony export */ });
/* harmony import */ var _constants__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! ../constants */ "./node_modules/wwpass-frontend/src/constants.js");

class WebSocketPool {
  constructor(options) {
    this.connectionPool = [];
    const defaultOptions = {
      spfewsAddress: 'wss://spfews.wwpass.com',
      clientKeyOnly: false,
      log: () => {}
    };
    this.options = {
      ...defaultOptions,
      ...options
    };
    this.promise = new Promise((resolve, reject) => {
      this.resolve = resolve;
      this.reject = reject;
    });
  }
  onError(status, reason, ticket) {
    this.reject({
      status,
      reason,
      ticket
    });
    this.close();
  }
  close() {
    while (this.connectionPool.length) {
      const connection = this.connectionPool.shift();
      if (connection.readyState === WebSocket.OPEN) {
        connection.close();
      }
    }
  }
  watchTicket(ticket) {
    if (!('WebSocket' in window)) {
      this.onError(_constants__WEBPACK_IMPORTED_MODULE_0__.WWPASS_STATUS.INTERNAL_ERROR, 'WebSocket is not supported.', ticket);
      return;
    }
    const socket = new WebSocket(this.options.spfewsAddress);
    this.connectionPool.push(socket);
    const {
      log
    } = this.options;
    let clientKey;
    let originalTicket = null;
    let ttl;
    socket.onopen = () => {
      try {
        log(`Connected: ${this.options.spfewsAddress}`);
        const message = JSON.stringify({
          ticket
        });
        log(`Sent message to server: ${message}`);
        socket.send(message);
      } catch (error) {
        log(error);
        this.onError(_constants__WEBPACK_IMPORTED_MODULE_0__.WWPASS_STATUS.INTERNAL_ERROR, 'WebSocket error', ticket);
      }
    };
    socket.onclose = () => {
      try {
        const index = this.connectionPool.indexOf(socket);
        if (index !== -1) {
          this.connectionPool.splice(index, 1);
        }
        log('Disconnected');
      } catch (error) {
        log(error);
        this.onError(_constants__WEBPACK_IMPORTED_MODULE_0__.WWPASS_STATUS.INTERNAL_ERROR, 'WebSocket error', ticket);
      }
    };
    socket.onmessage = message => {
      try {
        log(`Message received from server: ${message.data}`);
        const response = JSON.parse(message.data);
        const status = response.code;
        if ('clientKey' in response && !clientKey) {
          clientKey = response.clientKey;
          if (response.originalTicket !== undefined) {
            originalTicket = response.originalTicket;
            ttl = response.ttl;
          }
        }
        if (status === 200 || clientKey && this.options.clientKeyOnly) {
          this.resolve({
            status,
            reason: _constants__WEBPACK_IMPORTED_MODULE_0__.WWPASS_OK_MSG,
            clientKey,
            ticket,
            ttl,
            originalTicket: originalTicket !== null ? originalTicket : ticket
          });
          this.close();
        }
        // Skip all errors. Nothing to do about them
      } catch (error) {
        log(error);
        this.onError(_constants__WEBPACK_IMPORTED_MODULE_0__.WWPASS_STATUS.INTERNAL_ERROR, 'WebSocket error');
      }
    };
  }
}
/* harmony default export */ const __WEBPACK_DEFAULT_EXPORT__ = (WebSocketPool);

/***/ },

/***/ "./node_modules/wwpass-frontend/src/navigation.js"
/*!********************************************************!*\
  !*** ./node_modules/wwpass-frontend/src/navigation.js ***!
  \********************************************************/
(__unused_webpack_module, __webpack_exports__, __webpack_require__) {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   "default": () => (__WEBPACK_DEFAULT_EXPORT__)
/* harmony export */ });
/* harmony import */ var _urls__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! ./urls */ "./node_modules/wwpass-frontend/src/urls.js");

const navigateToCallback = options => {
  if (typeof options.callbackURL === 'function') {
    options.callbackURL((0,_urls__WEBPACK_IMPORTED_MODULE_0__.getCallbackURL)(options));
  } else {
    // URL string
    window.location.href = (0,_urls__WEBPACK_IMPORTED_MODULE_0__.getCallbackURL)(options);
  }
};
/* harmony default export */ const __WEBPACK_DEFAULT_EXPORT__ = (navigateToCallback);

/***/ },

/***/ "./node_modules/wwpass-frontend/src/nonce.js"
/*!***************************************************!*\
  !*** ./node_modules/wwpass-frontend/src/nonce.js ***!
  \***************************************************/
(__unused_webpack_module, __webpack_exports__, __webpack_require__) {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   copyClientNonce: () => (/* binding */ copyClientNonce),
/* harmony export */   generateClientNonce: () => (/* binding */ generateClientNonce),
/* harmony export */   getClientNonce: () => (/* binding */ getClientNonce),
/* harmony export */   getClientNonceIfNeeded: () => (/* binding */ getClientNonceIfNeeded)
/* harmony export */ });
/* harmony import */ var _ab__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! ./ab */ "./node_modules/wwpass-frontend/src/ab.js");
/* harmony import */ var _ticket__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! ./ticket */ "./node_modules/wwpass-frontend/src/ticket.js");
/* harmony import */ var _crypto__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(/*! ./crypto */ "./node_modules/wwpass-frontend/src/crypto.js");
/* harmony import */ var _error__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(/*! ./error */ "./node_modules/wwpass-frontend/src/error.js");
/* harmony import */ var _constants__WEBPACK_IMPORTED_MODULE_4__ = __webpack_require__(/*! ./constants */ "./node_modules/wwpass-frontend/src/constants.js");





const clean = items => {
  const currentDate = window.Date.now();
  return items.filter(item => item.deadline > currentDate);
};
const loadNonces = () => {
  const wwpassNonce = window.localStorage.getItem('wwpassNonce');
  if (!wwpassNonce) {
    return [];
  }
  try {
    return clean(JSON.parse(wwpassNonce));
  } catch (error) {
    window.localStorage.removeItem('wwpassNonce');
    throw error;
  }
};
const saveNonces = nonces => {
  window.localStorage.setItem('wwpassNonce', JSON.stringify(nonces));
};

// Retrieve client key nonce from local stroage
const getClientNonce = async (ticket, newTTL = null) => {
  if (!_crypto__WEBPACK_IMPORTED_MODULE_2__.haveCryptoAPI) {
    throw new _error__WEBPACK_IMPORTED_MODULE_3__["default"](_constants__WEBPACK_IMPORTED_MODULE_4__.WWPASS_STATUS.SSL_REQUIRED, 'Client-side encryption requires https.');
  }
  const nonces = loadNonces();
  const hash = await (0,_crypto__WEBPACK_IMPORTED_MODULE_2__.sha256)(ticket);
  const nonce = nonces.find(it => hash === it.hash);
  const key = nonce && nonce.key ? (0,_ab__WEBPACK_IMPORTED_MODULE_0__.b64ToAb)(nonce.key) : undefined;
  if (newTTL && key) {
    nonce.deadline = window.Date.now() + newTTL * 1000;
    saveNonces(nonces);
  }
  return key;
};

// generate Client Nonce and set it to localStorage
const generateClientNonce = async (ticket, ttl = 120) => {
  if (!_crypto__WEBPACK_IMPORTED_MODULE_2__.haveCryptoAPI) {
    throw new _error__WEBPACK_IMPORTED_MODULE_3__["default"](_constants__WEBPACK_IMPORTED_MODULE_4__.WWPASS_STATUS.SSL_REQUIRED, 'Client-side encryption requires https.');
  }
  const loadedKey = await getClientNonce(ticket);
  if (loadedKey) {
    return loadedKey;
  }
  const [rawKey, digest] = await Promise.all([(0,_crypto__WEBPACK_IMPORTED_MODULE_2__.generateKey)().then(key => (0,_crypto__WEBPACK_IMPORTED_MODULE_2__.exportKey)(key)), (0,_crypto__WEBPACK_IMPORTED_MODULE_2__.sha256)(ticket)]);
  const nonce = {
    hash: digest,
    key: (0,_ab__WEBPACK_IMPORTED_MODULE_0__.abToB64)(rawKey),
    deadline: window.Date.now() + ttl * 1000
  };
  const nonces = loadNonces();
  nonces.push(nonce);
  saveNonces(nonces);
  return rawKey;
};
const getClientNonceIfNeeded = async (ticket, ttl = 120) => {
  if (!(0,_ticket__WEBPACK_IMPORTED_MODULE_1__.isClientKeyTicket)(ticket)) {
    return undefined;
  }
  return generateClientNonce(ticket, ttl);
};
const copyClientNonce = (oldTicket, newTicket, ttl) => getClientNonce(oldTicket).then(nonceKey => (0,_crypto__WEBPACK_IMPORTED_MODULE_2__.sha256)(newTicket) // eslint-disable-line max-len
.then(digest => {
  const nonces = loadNonces();
  nonces.push({
    hash: digest,
    key: (0,_ab__WEBPACK_IMPORTED_MODULE_0__.abToB64)(nonceKey),
    deadline: window.Date.now() + ttl * 1000
  });
  saveNonces(nonces);
}));


/***/ },

/***/ "./node_modules/wwpass-frontend/src/open.js"
/*!**************************************************!*\
  !*** ./node_modules/wwpass-frontend/src/open.js ***!
  \**************************************************/
(__unused_webpack_module, __webpack_exports__, __webpack_require__) {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   "default": () => (__WEBPACK_DEFAULT_EXPORT__)
/* harmony export */ });
/* harmony import */ var _ticket__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! ./ticket */ "./node_modules/wwpass-frontend/src/ticket.js");
/* harmony import */ var _urls__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! ./urls */ "./node_modules/wwpass-frontend/src/urls.js");
/* harmony import */ var _crypto__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(/*! ./crypto */ "./node_modules/wwpass-frontend/src/crypto.js");
/* harmony import */ var _nonce__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(/*! ./nonce */ "./node_modules/wwpass-frontend/src/nonce.js");




const openWithTicket = initialOptions => new Promise(resolve => {
  const defaultOptions = {
    ttl: 120,
    callbackURL: '',
    ppx: 'wwp_',
    away: true
  };
  let options = {
    ...defaultOptions,
    ...initialOptions
  };
  const dh = (0,_urls__WEBPACK_IMPORTED_MODULE_1__.getCurrentDh)(window);
  if (dh) {
    options.dh = dh;
  }
  if ((0,_ticket__WEBPACK_IMPORTED_MODULE_0__.isClientKeyTicket)(options.ticket)) {
    (0,_nonce__WEBPACK_IMPORTED_MODULE_3__.generateClientNonce)(options.ticket, options.ttl).then(key => {
      options = {
        ...options,
        clientKey: (0,_crypto__WEBPACK_IMPORTED_MODULE_2__.encodeClientNonce)(key)
      };
      const url = (0,_urls__WEBPACK_IMPORTED_MODULE_1__.getUniversalURL)(options);
      if (options.away) {
        window.location.href = url;
      } else {
        resolve(url);
      }
    });
  } else {
    const url = (0,_urls__WEBPACK_IMPORTED_MODULE_1__.getUniversalURL)(options);
    if (options.away) {
      window.location.href = url;
    } else {
      resolve(url);
    }
  }
});
/* harmony default export */ const __WEBPACK_DEFAULT_EXPORT__ = (openWithTicket);

/***/ },

/***/ "./node_modules/wwpass-frontend/src/passkey/auth.js"
/*!**********************************************************!*\
  !*** ./node_modules/wwpass-frontend/src/passkey/auth.js ***!
  \**********************************************************/
(__unused_webpack_module, __webpack_exports__, __webpack_require__) {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   pluginPresent: () => (/* reexport safe */ _nm_interface__WEBPACK_IMPORTED_MODULE_6__.isNativeMessagingExtensionReady),
/* harmony export */   waitForRemoval: () => (/* binding */ waitForRemoval),
/* harmony export */   wwpassPasskeyAuth: () => (/* binding */ wwpassPasskeyAuth)
/* harmony export */ });
/* harmony import */ var _constants__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! ../constants */ "./node_modules/wwpass-frontend/src/constants.js");
/* harmony import */ var _ab__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! ../ab */ "./node_modules/wwpass-frontend/src/ab.js");
/* harmony import */ var _ticket__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(/*! ../ticket */ "./node_modules/wwpass-frontend/src/ticket.js");
/* harmony import */ var _getticket__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(/*! ../getticket */ "./node_modules/wwpass-frontend/src/getticket.js");
/* harmony import */ var _nonce__WEBPACK_IMPORTED_MODULE_4__ = __webpack_require__(/*! ../nonce */ "./node_modules/wwpass-frontend/src/nonce.js");
/* harmony import */ var _error__WEBPACK_IMPORTED_MODULE_5__ = __webpack_require__(/*! ../error */ "./node_modules/wwpass-frontend/src/error.js");
/* harmony import */ var _nm_interface__WEBPACK_IMPORTED_MODULE_6__ = __webpack_require__(/*! ./nm_interface */ "./node_modules/wwpass-frontend/src/passkey/nm_interface.js");
/* harmony import */ var _ui__WEBPACK_IMPORTED_MODULE_7__ = __webpack_require__(/*! ./ui */ "./node_modules/wwpass-frontend/src/passkey/ui.js");








const wwpassPlatformName = () => {
  const {
    userAgent
  } = navigator;
  const knownPlatforms = ['Android', 'iPhone', 'iPad'];
  for (let i = 0; i < knownPlatforms.length; i += 1) {
    if (userAgent.search(new RegExp(knownPlatforms[i], 'i')) !== -1) {
      return knownPlatforms[i];
    }
  }
  return null;
};
const wwpassCall = async (nmFunc, request) => {
  const platformName = wwpassPlatformName();
  if (platformName !== null) {
    await (0,_ui__WEBPACK_IMPORTED_MODULE_7__.wwpassNoSoftware)(_constants__WEBPACK_IMPORTED_MODULE_0__.WWPASS_STATUS.UNSUPPORTED_PLATFORM);
    throw new _error__WEBPACK_IMPORTED_MODULE_5__["default"](_constants__WEBPACK_IMPORTED_MODULE_0__.WWPASS_STATUS.UNSUPPORTED_PLATFORM, (0,_ui__WEBPACK_IMPORTED_MODULE_7__.wwpassMessageForPlatform)(platformName));
  }
  try {
    const result = await nmFunc(request);
    return result;
  } catch (err) {
    if (err instanceof _error__WEBPACK_IMPORTED_MODULE_5__["default"] && err.code === _constants__WEBPACK_IMPORTED_MODULE_0__.WWPASS_STATUS.NO_AUTH_INTERFACES_FOUND) {
      await (0,_ui__WEBPACK_IMPORTED_MODULE_7__.wwpassNoSoftware)(err.code);
    }
    throw err;
  }
};
const wwpassAuth = async request => wwpassCall(_nm_interface__WEBPACK_IMPORTED_MODULE_6__.wwpassNMExecute, {
  ...request,
  operation: 'auth'
});
const waitForRemoval = async () => wwpassCall(_nm_interface__WEBPACK_IMPORTED_MODULE_6__.nmWaitForRemoval);
const doWWPassPasskeyAuth = options => (0,_getticket__WEBPACK_IMPORTED_MODULE_3__.getTicket)(options.ticketURL).then(json => {
  const response = (0,_ticket__WEBPACK_IMPORTED_MODULE_2__.ticketAdapter)(json);
  const {
    ticket
  } = response;
  return (0,_nonce__WEBPACK_IMPORTED_MODULE_4__.getClientNonceIfNeeded)(ticket, response.ttl).then(key => wwpassAuth({
    ticket,
    clientKeyNonce: key !== undefined ? (0,_ab__WEBPACK_IMPORTED_MODULE_1__.abToB64)(key) : undefined,
    log: options.log
  })).then(() => ticket);
  /* We may receive new ticket here but we need
   * to keep the original one to find nonce */
});
const PASSKEY_BUTTON_TIMEOUT = 1000;
let recentlyClicked = false;
/* Setup the "Login with PassKey" button with appropriate event handler. */
const initPasskeyButton = (options, resolve, reject) => {
  const button = options.passkeyButton;

  // We render our desing only if provided element is empty
  if (button.innerHTML.length === 0) {
    button.appendChild((0,_ui__WEBPACK_IMPORTED_MODULE_7__.renderPassKeyButton)());
  }

  // Not using addEventListener so on reinit the previous handler is overwritten.
  button.onclick = e => {
    if (recentlyClicked === false) {
      // Setting up guard against rapid double clicking
      // TODO: display a loader while the operation is in progress
      recentlyClicked = true;
      let enableButtonTimer = setTimeout(() => {
        recentlyClicked = false;
        enableButtonTimer = false;
      }, PASSKEY_BUTTON_TIMEOUT);
      doWWPassPasskeyAuth(options).then(newTicket => {
        resolve({
          ppx: options.ppx,
          version: options.version,
          code: _constants__WEBPACK_IMPORTED_MODULE_0__.WWPASS_STATUS.OK,
          message: _constants__WEBPACK_IMPORTED_MODULE_0__.WWPASS_OK_MSG,
          ticket: newTicket,
          callbackURL: options.callbackURL,
          hw: true
        });
      }).catch(err => {
        if (!err.code) {
          options.log('PassKey error: ', err);
        } else if (err.code === _constants__WEBPACK_IMPORTED_MODULE_0__.WWPASS_STATUS.INTERNAL_ERROR || options.returnErrors) {
          reject({
            ppx: options.ppx,
            version: options.version,
            code: err.code,
            message: err.message,
            callbackURL: options.callbackURL
          });
        }
      }).finally(() => {
        if (enableButtonTimer !== false) {
          clearTimeout(enableButtonTimer);
          enableButtonTimer = false;
          recentlyClicked = false;
        }
      });
    }
    e.preventDefault();
  };
};
const wwpassPasskeyAuth = initialOptions => new Promise((resolve, reject) => {
  const defaultOptions = {
    ticketURL: '',
    callbackURL: '',
    ppx: 'wwp_',
    forcePasskeyButton: true,
    log: () => {}
  };
  const options = {
    ...defaultOptions,
    ...initialOptions
  };
  if (!options.passkeyButton) {
    reject({
      ppx: options.ppx,
      version: options.version,
      code: _constants__WEBPACK_IMPORTED_MODULE_0__.WWPASS_STATUS.INTERNAL_ERROR,
      message: 'Cannot find passkey element',
      callbackURL: options.callbackURL
    });
  }

  // Wait for WWPass Extension initialization and then render the button
  if (options.forcePasskeyButton || (0,_nm_interface__WEBPACK_IMPORTED_MODULE_6__.isNativeMessagingExtensionReady)()) {
    if (options.passkeyButton.style.display === 'none') {
      options.passkeyButton.style.display = null;
    }
    initPasskeyButton(options, resolve, reject);
  } else {
    const displayBackup = options.passkeyButton.style.display;
    options.passkeyButton.style.display = 'none';
    const observer = new MutationObserver((_mutationsList, _observer) => {
      if ((0,_nm_interface__WEBPACK_IMPORTED_MODULE_6__.isNativeMessagingExtensionReady)()) {
        _observer.disconnect();
        options.passkeyButton.style.display = displayBackup === 'none' ? null : displayBackup;
        initPasskeyButton(options, resolve, reject);
      }
    });
    observer.observe(document.head, {
      childList: true
    });
  }
});


/***/ },

/***/ "./node_modules/wwpass-frontend/src/passkey/nm_interface.js"
/*!******************************************************************!*\
  !*** ./node_modules/wwpass-frontend/src/passkey/nm_interface.js ***!
  \******************************************************************/
(__unused_webpack_module, __webpack_exports__, __webpack_require__) {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   isNativeMessagingExtensionReady: () => (/* binding */ isNativeMessagingExtensionReady),
/* harmony export */   nmWaitForRemoval: () => (/* binding */ nmWaitForRemoval),
/* harmony export */   wwpassNMExecute: () => (/* binding */ wwpassNMExecute)
/* harmony export */ });
/* harmony import */ var _constants__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! ../constants */ "./node_modules/wwpass-frontend/src/constants.js");
/* harmony import */ var _util__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! ../util */ "./node_modules/wwpass-frontend/src/util.js");
/* harmony import */ var _ui__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(/*! ./ui */ "./node_modules/wwpass-frontend/src/passkey/ui.js");
/* harmony import */ var _ui_elements__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(/*! ./ui_elements */ "./node_modules/wwpass-frontend/src/passkey/ui_elements.js");
/* harmony import */ var _error__WEBPACK_IMPORTED_MODULE_4__ = __webpack_require__(/*! ../error */ "./node_modules/wwpass-frontend/src/error.js");





const EXTENSION_POLL_TIMEOUT = 200;
const EXTENSION_POLL_ATTEMPTS = 15;
let extensionNotInstalled = false;
const isNativeMessagingExtensionReady = () => (document.querySelector('meta[property="wwpass:extension:version"]') || document.getElementById('_WWAuth_Chrome_Installed_')) !== null;
const getNMresult = id => new Promise(reslove => {
  window.addEventListener('message', function onMessageCallee(event) {
    if (event.data.type === '_WWAuth_Message' && event.data.src === 'plugin' && event.data.id === id) {
      window.removeEventListener('message', onMessageCallee, false);
      reslove(event.data);
    }
  }, false);
});
const waitForExtension = async (timeout, attempts) => {
  let attemptsRemaining = attempts;
  while (!isNativeMessagingExtensionReady()) {
    if (attemptsRemaining <= 0) {
      return false;
    }
    // eslint-disable-next-line no-await-in-loop
    await (0,_util__WEBPACK_IMPORTED_MODULE_1__.wait)(timeout);
    attemptsRemaining -= 1;
  }
  return true;
};
const randomID = () => ((1 + Math.random()) * 0x100000000 | 0).toString(16).substring(1); // eslint-disable-line no-bitwise,max-len

const wwpassNMCall = async (func, args, log = () => {}) => {
  if (extensionNotInstalled) {
    log('%s: chrome native messaging extension is not installed', 'wwpassNMExecute');
    throw new _error__WEBPACK_IMPORTED_MODULE_4__["default"](_constants__WEBPACK_IMPORTED_MODULE_0__.WWPASS_STATUS.NO_AUTH_INTERFACES_FOUND, _ui_elements__WEBPACK_IMPORTED_MODULE_3__.noAuthInterfacesMessage);
  }
  if (!(await waitForExtension(EXTENSION_POLL_TIMEOUT, EXTENSION_POLL_ATTEMPTS))) {
    extensionNotInstalled = true;
    log('%s: chrome native messaging extension is not installed', 'wwpassNMExecute');
    throw new _error__WEBPACK_IMPORTED_MODULE_4__["default"](_constants__WEBPACK_IMPORTED_MODULE_0__.WWPASS_STATUS.NO_AUTH_INTERFACES_FOUND, _ui_elements__WEBPACK_IMPORTED_MODULE_3__.noAuthInterfacesMessage);
  }
  const id = randomID();
  window.postMessage({
    type: '_WWAuth_Message',
    src: 'client',
    id,
    func,
    args: args ? JSON.parse(JSON.stringify(args)) : args
  }, '*');
  const result = await getNMresult(id);
  if (result.code !== _constants__WEBPACK_IMPORTED_MODULE_0__.WWPASS_STATUS.OK) {
    if (result.code === _constants__WEBPACK_IMPORTED_MODULE_0__.WWPASS_STATUS.NO_AUTH_INTERFACES_FOUND) {
      await (0,_ui__WEBPACK_IMPORTED_MODULE_2__.wwpassShowError)(_ui_elements__WEBPACK_IMPORTED_MODULE_3__.noSecurityPack, 'WWPass Error');
    }
    throw new _error__WEBPACK_IMPORTED_MODULE_4__["default"](result.code, result.ticketOrMessage);
  }
  return result.ticketOrMessage;
};
const wwpassNMExecute = inputRequest => {
  const defaultOptions = {
    log: () => {}
  };
  const request = {
    ...defaultOptions,
    ...inputRequest
  };
  const {
    log
  } = request;
  delete request.log;
  log('%s: called', 'wwpassNMExecute');
  request.uri = {
    domain: window.location.hostname,
    protocol: window.location.protocol
  };
  return wwpassNMCall('exec', [request], log);
};
const nmWaitForRemoval = (log = () => {}) => wwpassNMCall('on_key_rm', undefined, log);


/***/ },

/***/ "./node_modules/wwpass-frontend/src/passkey/ui.js"
/*!********************************************************!*\
  !*** ./node_modules/wwpass-frontend/src/passkey/ui.js ***!
  \********************************************************/
(__unused_webpack_module, __webpack_exports__, __webpack_require__) {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   renderPassKeyButton: () => (/* binding */ renderPassKeyButton),
/* harmony export */   wwpassMessageForPlatform: () => (/* binding */ wwpassMessageForPlatform),
/* harmony export */   wwpassNoSoftware: () => (/* binding */ wwpassNoSoftware),
/* harmony export */   wwpassShowError: () => (/* binding */ wwpassShowError)
/* harmony export */ });
/* harmony import */ var _constants__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! ../constants */ "./node_modules/wwpass-frontend/src/constants.js");
/* harmony import */ var _ui_elements__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! ./ui_elements */ "./node_modules/wwpass-frontend/src/passkey/ui_elements.js");


const isNativeMessaging = () => {
  const {
    userAgent
  } = navigator;
  let re = /Firefox\/([0-9]+)\./;
  let match = userAgent.match(re);
  if (match && match.length > 1) {
    const version = match[1];
    if (Number(version) >= 51) {
      return 'Firefox';
    }
  }
  re = /Chrome\/([0-9]+)\./;
  match = userAgent.match(re);
  if (match && match.length > 1) {
    const version = match[1];
    if (Number(version) >= 45) {
      return 'Chrome';
    }
  }
  return false;
};
const wwpassPlatformName = () => {
  const {
    userAgent
  } = navigator;
  const knownPlatforms = ['Android', 'iPhone', 'iPad'];
  for (let i = 0; i < knownPlatforms.length; i += 1) {
    if (userAgent.search(new RegExp(knownPlatforms[i], 'i')) !== -1) {
      return knownPlatforms[i];
    }
  }
  return null;
};
const wwpassMessageForPlatform = platformName => `${_ui_elements__WEBPACK_IMPORTED_MODULE_1__.unsupprotedPlatfromMessage} ${platformName}`;
const wwpassShowError = (message, title) => new Promise(resolve => {
  if (!document.getElementById('_wwpass_css')) {
    const l = document.createElement('style');
    l.id = '_wwpass_css';
    l.innerText = _ui_elements__WEBPACK_IMPORTED_MODULE_1__.errorDialogCSS;
    document.head.appendChild(l);
  }
  const dlg = document.createElement('div');
  dlg.id = '_wwpass_err_dlg';
  const dlgClose = document.createElement('span');
  dlgClose.innerHTML = 'Close';
  dlgClose.id = '_wwpass_err_close';
  const header = document.createElement('h1');
  header.innerHTML = title;
  const text = document.createElement('div');
  text.innerHTML = message;
  dlg.appendChild(header);
  dlg.appendChild(text);
  dlg.appendChild(dlgClose);
  document.body.appendChild(dlg);
  document.getElementById('_wwpass_err_close').addEventListener('click', () => {
    const elem = document.getElementById('_wwpass_err_dlg');
    elem.parentNode.removeChild(elem);
    resolve();
  });
});
const wwpassNoSoftware = async code => {
  if (code === _constants__WEBPACK_IMPORTED_MODULE_0__.WWPASS_STATUS.NO_AUTH_INTERFACES_FOUND) {
    const client = isNativeMessaging();
    let message = '';
    if (client) {
      if (client === 'Chrome') {
        message = (0,_ui_elements__WEBPACK_IMPORTED_MODULE_1__.noChromeExtension)(window.location.href);
      } else if (client === 'Firefox') {
        // Firefox
        message = (0,_ui_elements__WEBPACK_IMPORTED_MODULE_1__.noFirefoxExtension)(window.location.href);
      } else {
        // Wait for Edge extension
      }
    } else {
      message = _ui_elements__WEBPACK_IMPORTED_MODULE_1__.noSecurityPack;
    }
    await wwpassShowError(message, 'WWPass &mdash; No Software Found');
  } else if (code === _constants__WEBPACK_IMPORTED_MODULE_0__.WWPASS_STATUS.UNSUPPORTED_PLATFORM) {
    await wwpassShowError(wwpassMessageForPlatform(wwpassPlatformName()), 'WWPass &mdash; Unsupported Platform');
  }
};
const renderPassKeyButton = () => {
  const button = document.createElement('button');
  button.innerHTML = _ui_elements__WEBPACK_IMPORTED_MODULE_1__.passkeyButtonHTML;
  button.setAttribute('style', _ui_elements__WEBPACK_IMPORTED_MODULE_1__.passkeyButtonCSS);
  return button;
};


/***/ },

/***/ "./node_modules/wwpass-frontend/src/passkey/ui_elements.js"
/*!*****************************************************************!*\
  !*** ./node_modules/wwpass-frontend/src/passkey/ui_elements.js ***!
  \*****************************************************************/
(__unused_webpack_module, __webpack_exports__, __webpack_require__) {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   errorDialogCSS: () => (/* binding */ errorDialogCSS),
/* harmony export */   noAuthInterfacesMessage: () => (/* binding */ noAuthInterfacesMessage),
/* harmony export */   noChromeExtension: () => (/* binding */ noChromeExtension),
/* harmony export */   noFirefoxExtension: () => (/* binding */ noFirefoxExtension),
/* harmony export */   noSecurityPack: () => (/* binding */ noSecurityPack),
/* harmony export */   passkeyButtonCSS: () => (/* binding */ passkeyButtonCSS),
/* harmony export */   passkeyButtonHTML: () => (/* binding */ passkeyButtonHTML),
/* harmony export */   unsupprotedPlatfromMessage: () => (/* binding */ unsupprotedPlatfromMessage)
/* harmony export */ });
const noSecurityPack = `
<p>No Security Pack is found on your computer or WWPass&nbsp;native&nbsp;host is not responding.</p>
<p>To install Security Pack visit <a href="https://ks.wwpass.com/download/">Key Services</a></p>
<p><a href="https://support.wwpass.com/?topic=604">Learn more...</a></p>`;
const noChromeExtension = returnURL => `
<p>The WWPass Authentication extension for Chrome is not installed or is disabled in browser settings.</p>
<p>Click the link below to install and enable the WWPass Authentication extension.</p>
<p><a href="https://chrome.wwpass.com/?callbackURL=${encodeURIComponent(returnURL)}">Install WWPass Authentication Extension</a>`;
const noFirefoxExtension = returnURL => `
<p>The WWPass Authentication extension for Firefox is not installed or is disabled in browser settings.</p>
<p>Click the link below to install and enable the WWPass Authentication extension.</p>
<p><a href="https://firefox.wwpass.com/?callbackURL=${encodeURIComponent(returnURL)}">Install WWPass Authentication Extension</a>`;
const noAuthInterfacesMessage = 'No WWPass SecurityPack is found on your computer or WWPass Browser Plugin is disabled';
const unsupprotedPlatfromMessage = 'WWPass authentication is not supported on';
const errorDialogCSS = `#_wwpass_err_dlg {
  display: block;
  position: fixed;
  top: 20%;
  left: 50%;
  width: 550px;
  margin-left: -315px; /* -(width + padding-left)px */

  padding: 20px 40px;
  background-color: #eee;
  font-family: "Helvetica Neue", Helvetica, Arial, sans-serif;
  font-weight: 300;
  box-shadow: 0 2px 5px;

  z-index: 1337;
  }

  #_wwpass_err_dlg a {
      color: #0074d9;
      }

  #_wwpass_err_dlg h1 {
      font-size: 1.3em;
      font-weight: 300;
      margin-bottom: 30px;
      }

#_wwpass_err_close {
  text-decoration: none;
  color: #0074d9;
  cursor: pointer;

  margin: 0 auto;
  display: block;
  max-width: 40px;
  min-width: 35px;

  margin-top: 30px;
  }

@media (max-width: 700px) {
  #_wwpass_err_dlg {
      width: 100%;
      height: 100%;
      margin: 0;
      left: 0;
      top: 0;
      padding: 10px;
      }

  #_wwpass_err_close {
      margin-top: 1em;
      }
}`;
const passkeyButtonHTML = `<svg id="icon-button_logo" viewBox="0 0 34 20" style="fill: none; left: 28px; stroke-width: 2px; width: 35px; height: 25px; top: 5px; position: absolute;">
<switch><g><title>button_logo</title><path fill="#FFF" d="M31.2 20h-28c-1.7 0-3-1.3-3-3V3c0-1.7 1.3-3 3-3h27.4C32.5 0 34 1.6 34 3.6c0 1.3-.8 2.5-1.9 3L34 16.8c.2 1.6-.9 3-2.5 3.1-.1.1-.2.1-.3.1zM27 6h-1c-1.1 0-2 .9-2 2v1h-8.3c-.8-2.8-3.8-4.4-6.5-3.5S4.8 9.2 5.6 12s3.8 4.4 6.5 3.5c1.7-.5 3-1.8 3.5-3.5H27V6zm-1 1c-.6 0-1 .4-1 1v2H12.1V8.3c0-.2-.1-.3-.2-.3h-.2l-3.6 2.3c-.1.1-.2.3-.1.4l.1.1 3.6 2.2c.1.1.3 0 .4-.1V11H26V7z"></path></g></switch></svg>
Log in with PassKey`;
const passkeyButtonCSS = `color: white;
background-color: #2277E6;
font-weight: 400;
font-size: 18px;
line-height: 36px;
font-family: "Arial", sans-serif;
padding-right: 15px;
padding-left: 60px;
cursor: pointer;
height: 40px;
width: 255px;
border-radius: 3px;
border: 1px solid #2277E6;
text-decoration: none;
position: relative;`;


/***/ },

/***/ "./node_modules/wwpass-frontend/src/ticket.js"
/*!****************************************************!*\
  !*** ./node_modules/wwpass-frontend/src/ticket.js ***!
  \****************************************************/
(__unused_webpack_module, __webpack_exports__, __webpack_require__) {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   getShortTicketForm: () => (/* binding */ getShortTicketForm),
/* harmony export */   isClientKeyTicket: () => (/* binding */ isClientKeyTicket),
/* harmony export */   ticketAdapter: () => (/* binding */ ticketAdapter)
/* harmony export */ });
const isClientKeyTicket = ticket => {
  const [info] = ticket.split('@');
  const spnameFlagsOTP = info.split(':');
  if (spnameFlagsOTP.length < 3) {
    return false;
  }
  const FLAGS_INDEX = 1; // second element of ticket — flags
  const flags = spnameFlagsOTP[FLAGS_INDEX];
  return flags.split('').some(element => element === 'c');
};

/* Remove part of OTP from ticket so it can be safely displayed in QR code */
const getShortTicketForm = ticket => {
  const SHORT_TICKET_LENGTH = 8; // bytes
  const infoHost = ticket.split('@');
  const spnameFlagsOTP = infoHost[0].split(':');
  const otp = spnameFlagsOTP[spnameFlagsOTP.length - 1];
  return `${spnameFlagsOTP[0]}:${spnameFlagsOTP.length === 3 ? `${spnameFlagsOTP[1]}:` : ''}${otp.substr(0, SHORT_TICKET_LENGTH * 2)}@${infoHost[1]}`;
};
const ticketAdapter = response => {
  if (response && response.data) {
    const ticket = {
      ticket: response.data,
      ttl: response.ttl || 120
    };
    delete ticket.data;
    return ticket;
  }
  return response;
};


/***/ },

/***/ "./node_modules/wwpass-frontend/src/urls.js"
/*!**************************************************!*\
  !*** ./node_modules/wwpass-frontend/src/urls.js ***!
  \**************************************************/
(__unused_webpack_module, __webpack_exports__, __webpack_require__) {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   getCallbackURL: () => (/* binding */ getCallbackURL),
/* harmony export */   getCurrentDh: () => (/* binding */ getCurrentDh),
/* harmony export */   getUniversalURL: () => (/* binding */ getUniversalURL)
/* harmony export */ });
/* harmony import */ var _constants__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! ./constants */ "./node_modules/wwpass-frontend/src/constants.js");

const getCallbackURL = (initialOptions = {}) => {
  const defaultOptions = {
    ppx: 'wwp_',
    version: _constants__WEBPACK_IMPORTED_MODULE_0__.PROTOCOL_VERSION,
    status: 200,
    reason: 'OK',
    ticket: undefined,
    callbackURL: undefined,
    hw: false // hardware legacy
  };
  const options = {
    ...defaultOptions,
    ...initialOptions
  };
  let url = '';
  if (typeof options.callbackURL === 'string') {
    url = options.callbackURL;
  }
  const firstDelimiter = url.indexOf('?') === -1 ? '?' : '&';
  url += firstDelimiter;
  const callbackParameters = ['version', 'ticket', 'status', 'reason'];
  if (options.hw) {
    callbackParameters.push('hw');
    options.hw = 1;
  }
  callbackParameters.forEach((name, index) => {
    url += `${encodeURIComponent(options.ppx)}${name}=${encodeURIComponent(options[name])}${index === callbackParameters.length - 1 ? '' : '&'}`;
  });
  return url;
};
const getCurrentDh = w => w.screen.height - w.innerHeight;
const getUniversalURL = (initialOptions = {}, forQRCode = false) => {
  const defaultOptions = {
    universal: false,
    operation: 'auth',
    ppx: 'wwp_',
    version: _constants__WEBPACK_IMPORTED_MODULE_0__.PROTOCOL_VERSION,
    ticket: undefined,
    callbackURL: undefined,
    clientKey: undefined,
    dh: undefined
  };
  const options = {
    ...defaultOptions,
    ...initialOptions
  };
  let url = options.universal ? 'https://get.wwpass.com/' : 'wwpass://';
  if (options.operation === 'auth') {
    url += 'auth';
    url += `?v=${options.version}`;
    url += `&t=${encodeURIComponent(forQRCode ? options.shortTicket : options.ticket)}`;
    url += `&ppx=${encodeURIComponent(options.ppx)}`;
    if (options.clientKey) {
      url += `&ck=${options.clientKey}`;
    }
    if (options.callbackURL && !forQRCode) {
      url += `&c=${encodeURIComponent(options.callbackURL)}`;
    }
  } else {
    url += `${encodeURIComponent(options.operation)}?t=${encodeURIComponent(options.ticket)}`;
  }
  const dh = getCurrentDh(window) || 0;
  if (dh) {
    url += `&dh=${dh}`;
  }
  return url;
};


/***/ },

/***/ "./node_modules/wwpass-frontend/src/util.js"
/*!**************************************************!*\
  !*** ./node_modules/wwpass-frontend/src/util.js ***!
  \**************************************************/
(__unused_webpack_module, __webpack_exports__, __webpack_require__) {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   absolutePath: () => (/* binding */ absolutePath),
/* harmony export */   concatBuffers: () => (/* binding */ concatBuffers),
/* harmony export */   hexlify: () => (/* binding */ hexlify),
/* harmony export */   wait: () => (/* binding */ wait)
/* harmony export */ });
const wait = ms => ms ? new Promise(r => {
  setTimeout(r, ms);
}) : Promise.resolve(null);
const absolutePath = href => {
  const link = document.createElement('a');
  link.href = href;
  return link.href;
};
const concatBuffers = (...args) => {
  const totalLen = args.reduce((accumulator, curentAB) => accumulator + curentAB.byteLength, 0);
  let i = 0;
  const result = new Uint8Array(totalLen);
  while (args.length > 0) {
    result.set(new Uint8Array(args[0]), i);
    i += args[0].byteLength;
    args.shift();
  }
  return result.buffer;
};

// Hexlify binary buffer
const hexlify = buffer => {
  const hexCodes = [];
  const view = new DataView(buffer);
  for (let i = 0; i < view.byteLength; i += 4) {
    // Using getUint32 reduces the number of iterations needed (we process 4 bytes each time)
    const value = view.getUint32(i);
    // toString(16) will give the hex representation of the number without padding
    const stringValue = value.toString(16);
    // We use concatenation and slice for padding
    const padding = '00000000';
    const paddedValue = (padding + stringValue).slice(-padding.length);
    hexCodes.push(paddedValue);
  }

  // Join all the hex strings into one
  return hexCodes.join('');
};


/***/ },

/***/ "./node_modules/wwpass-frontend/src/wwpass.crypto.js"
/*!***********************************************************!*\
  !*** ./node_modules/wwpass-frontend/src/wwpass.crypto.js ***!
  \***********************************************************/
(__unused_webpack_module, __webpack_exports__, __webpack_require__) {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   WWPassCrypto: () => (/* binding */ WWPassCrypto),
/* harmony export */   WWPassCryptoPromise: () => (/* binding */ WWPassCryptoPromise)
/* harmony export */ });
/* harmony import */ var _mobile_wwpass_websocket__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! ./mobile/wwpass.websocket */ "./node_modules/wwpass-frontend/src/mobile/wwpass.websocket.js");
/* harmony import */ var _ab__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! ./ab */ "./node_modules/wwpass-frontend/src/ab.js");
/* harmony import */ var _crypto__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(/*! ./crypto */ "./node_modules/wwpass-frontend/src/crypto.js");
/* harmony import */ var _util__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(/*! ./util */ "./node_modules/wwpass-frontend/src/util.js");
/* harmony import */ var _nonce__WEBPACK_IMPORTED_MODULE_4__ = __webpack_require__(/*! ./nonce */ "./node_modules/wwpass-frontend/src/nonce.js");





const clientKeyIV = new Uint8Array([176, 178, 97, 142, 156, 31, 45, 30, 81, 210, 85, 14, 202, 203, 86, 240]);
class WWPassCryptoPromise {
  /* Return Promise that will be resloved to actual crypto object
  with encrypt/decrypt String/ArrayBuffer methods and cleintKey member.
  Ticket must be authenticated with 'c' auth factor.
  Only supported values for algorithm are 'AES-GCM' and 'AES-CBC'.
  */
  static getWWPassCrypto(ticket, algorithmName = 'AES-GCM') {
    let encryptedClientKey = null;
    const algorithm = {
      name: algorithmName,
      length: 256
    };
    const websocketPool = new _mobile_wwpass_websocket__WEBPACK_IMPORTED_MODULE_0__["default"]({
      clientKeyOnly: true
    });
    websocketPool.watchTicket(ticket);
    return websocketPool.promise.then(result => {
      if (!result.clientKey) {
        throw Error(`No client key associated with the ticket ${ticket}`);
      }
      encryptedClientKey = result.clientKey;
      return (0,_nonce__WEBPACK_IMPORTED_MODULE_4__.getClientNonce)(result.originalTicket ? result.originalTicket : ticket, result.ttl);
    }).then(key => {
      if (!key) {
        throw new Error('No client key nonce associated with the ticket in this browser');
      }
      return (0,_crypto__WEBPACK_IMPORTED_MODULE_2__.importKey)(key, {
        name: 'AES-CBC'
      }, false, ['encrypt', 'decrypt', 'wrapKey', 'unwrapKey']);
    }).then(clientKeyNonce => (0,_crypto__WEBPACK_IMPORTED_MODULE_2__.decrypt)({
      name: 'AES-CBC',
      iv: clientKeyIV
    }, clientKeyNonce, (0,_ab__WEBPACK_IMPORTED_MODULE_1__.b64ToAb)(encryptedClientKey))).then(arrayBuffer => (0,_crypto__WEBPACK_IMPORTED_MODULE_2__.importKey)(arrayBuffer, algorithm, false, ['encrypt', 'decrypt', 'wrapKey', 'unwrapKey'])).then(key => new WWPassCryptoPromise(key, algorithm)).catch(error => {
      if (error.reason !== undefined) {
        throw new Error(error.reason);
      }
      throw error;
    });
  }
  encryptArrayBuffer(arrayBuffer) {
    const iv = new Uint8Array(this.ivLen);
    (0,_crypto__WEBPACK_IMPORTED_MODULE_2__.getRandomData)(iv);
    const {
      algorithm
    } = this;
    Object.assign(algorithm, {
      iv
    });
    return (0,_crypto__WEBPACK_IMPORTED_MODULE_2__.encrypt)(algorithm, this.clientKey, arrayBuffer).then(encryptedAB => (0,_util__WEBPACK_IMPORTED_MODULE_3__.concatBuffers)(iv.buffer, encryptedAB));
  }
  encryptString(string) {
    return this.encryptArrayBuffer((0,_ab__WEBPACK_IMPORTED_MODULE_1__.str2ab)(string)).then(_ab__WEBPACK_IMPORTED_MODULE_1__.abToB64);
  }
  decryptArrayBuffer(encryptedArrayBuffer) {
    const {
      algorithm
    } = this;
    Object.assign(algorithm, {
      iv: encryptedArrayBuffer.slice(0, this.ivLen)
    });
    return (0,_crypto__WEBPACK_IMPORTED_MODULE_2__.decrypt)(algorithm, this.clientKey, encryptedArrayBuffer.slice(this.ivLen));
  }
  decryptString(encryptedString) {
    return this.decryptArrayBuffer((0,_ab__WEBPACK_IMPORTED_MODULE_1__.b64ToAb)(encryptedString)).then(_ab__WEBPACK_IMPORTED_MODULE_1__.ab2str);
  }

  // Private
  constructor(key, algorithm) {
    this.ivLen = algorithm.name === 'AES-GCM' ? 12 : 16;
    this.algorithm = algorithm;
    if (algorithm.name === 'AES-GCM') {
      Object.assign(this.algorithm, {
        tagLength: 128
      });
    }
    this.clientKey = key;
  }
}
class WWPassCrypto {
  constructor(ticket, algorithm) {
    this.cryptoPromise = WWPassCryptoPromise.getWWPassCrypto(ticket, algorithm);
  }
  encryptArrayBuffer(arrayBuffer) {
    return this.cryptoPromise.then(crypto => crypto.encryptArrayBuffer(arrayBuffer));
  }
  encryptString(string) {
    return this.cryptoPromise.then(crypto => crypto.encryptString(string));
  }
  decryptArrayBuffer(encryptedArrayBuffer) {
    return this.cryptoPromise.then(crypto => crypto.decryptArrayBuffer(encryptedArrayBuffer));
  }
  decryptString(encryptedString) {
    return this.cryptoPromise.then(crypto => crypto.decryptString(encryptedString));
  }
}


/***/ }

/******/ 	});
/************************************************************************/
/******/ 	// The module cache
/******/ 	var __webpack_module_cache__ = {};
/******/ 	
/******/ 	// The require function
/******/ 	function __webpack_require__(moduleId) {
/******/ 		// Check if module is in cache
/******/ 		var cachedModule = __webpack_module_cache__[moduleId];
/******/ 		if (cachedModule !== undefined) {
/******/ 			return cachedModule.exports;
/******/ 		}
/******/ 		// Create a new module (and put it into the cache)
/******/ 		var module = __webpack_module_cache__[moduleId] = {
/******/ 			// no module.id needed
/******/ 			// no module.loaded needed
/******/ 			exports: {}
/******/ 		};
/******/ 	
/******/ 		// Execute the module function
/******/ 		if (!(moduleId in __webpack_modules__)) {
/******/ 			delete __webpack_module_cache__[moduleId];
/******/ 			var e = new Error("Cannot find module '" + moduleId + "'");
/******/ 			e.code = 'MODULE_NOT_FOUND';
/******/ 			throw e;
/******/ 		}
/******/ 		__webpack_modules__[moduleId](module, module.exports, __webpack_require__);
/******/ 	
/******/ 		// Return the exports of the module
/******/ 		return module.exports;
/******/ 	}
/******/ 	
/************************************************************************/
/******/ 	/* webpack/runtime/define property getters */
/******/ 	(() => {
/******/ 		// define getter functions for harmony exports
/******/ 		__webpack_require__.d = (exports, definition) => {
/******/ 			for(var key in definition) {
/******/ 				if(__webpack_require__.o(definition, key) && !__webpack_require__.o(exports, key)) {
/******/ 					Object.defineProperty(exports, key, { enumerable: true, get: definition[key] });
/******/ 				}
/******/ 			}
/******/ 		};
/******/ 	})();
/******/ 	
/******/ 	/* webpack/runtime/hasOwnProperty shorthand */
/******/ 	(() => {
/******/ 		__webpack_require__.o = (obj, prop) => (Object.prototype.hasOwnProperty.call(obj, prop))
/******/ 	})();
/******/ 	
/******/ 	/* webpack/runtime/make namespace object */
/******/ 	(() => {
/******/ 		// define __esModule on exports
/******/ 		__webpack_require__.r = (exports) => {
/******/ 			if(typeof Symbol !== 'undefined' && Symbol.toStringTag) {
/******/ 				Object.defineProperty(exports, Symbol.toStringTag, { value: 'Module' });
/******/ 			}
/******/ 			Object.defineProperty(exports, '__esModule', { value: true });
/******/ 		};
/******/ 	})();
/******/ 	
/************************************************************************/
var __webpack_exports__ = {};
// This entry needs to be wrapped in an IIFE because it needs to be in strict mode.
(() => {
"use strict";
/*!*************************!*\
  !*** ./src/js/login.js ***!
  \*************************/
__webpack_require__.r(__webpack_exports__);
/* harmony import */ var wwpass_frontend__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! wwpass-frontend */ "./node_modules/wwpass-frontend/src/lib.js");
// import $ from 'jquery';

let urlBase = window.location.href;
urlBase = `${urlBase.substring(0, urlBase.lastIndexOf('/'))}/`;
function supportsHtml5Storage() {
  try {
    return 'localStorage' in window && window.localStorage !== null;
  } catch (e) {
    return false;
  }
}
function compatibleBrowser() {
  if (!supportsHtml5Storage()) {
    return false;
  }
  if (window.msCrypto) {
    return false;
  }
  if (!window.crypto) {
    return false;
  }
  if (window.crypto.subtle || window.crypto.webkitSubtle) {
    return true;
  }
  return false;
}
const isIOS = navigator.userAgent.match(/iPhone|iPod|iPad/i) || navigator.userAgent.match(/Intel Mac OS X/i) && navigator.maxTouchPoints > 1; // crazy ios13 on iPad..

const isAndroid = navigator.userAgent.match(/Android/i) || navigator.userAgent.match(/Samsung/i) && navigator.userAgent.match(/Linux/i);
const mobileDevice = isIOS || isAndroid;
function isSafariPrivateMode() {
  const isSafari = navigator.userAgent.match(/Version\/([0-9\._]+).*Safari/);
  if (!isSafari || !isIOS) {
    return false;
  }
  const version = parseInt(isSafari[1], 10);
  if (version >= 11) {
    try {
      window.openDatabase(null, null, null, null);
      return false;
    } catch (_) {
      return true;
    }
  } else if (version === 10) {
    if (localStorage.length) {
      return false;
    }
    try {
      localStorage.test = 1;
      localStorage.removeItem('test');
      return false;
    } catch (_) {
      return true;
    }
  }
  return false;
}
if (isSafariPrivateMode()) {
  if (window.location.href.includes("debug")) {
    alert('Safari private mode detected');
  } else {
    window.location.href = 'error_page.php?js=SafariPrivateMode';
  }
}
if (!navigator.userAgent.match(/electron/)) {
  if (window.location.protocol !== 'https:' && window.location.hostname !== 'localhost' && window.location.hostname !== '127.0.0.1' && !window.location.hostname.endsWith('.localhost')) {
    window.location.href = 'notsupported.php?js=2';
  } else if (!compatibleBrowser()) {
    window.location.href = 'notsupported.php?js=1';
  }
}
function uiCallback(ev) {
  if (!ev) {
    return;
  }
  // only for legacy design, buth passhub.net and business  
  if (!document.querySelector("#qrtext")) {
    // new passhub.net design
    return;
  }

  // const event = JSON.stringify(ev);
  const heading_public = document.querySelector('.heading--margin-top-big');
  if (heading_public) {
    // passhub.net

    if ('button' in ev) {
      document.querySelector("#qrtext").style.display = "none";
      document.querySelector('.qrblock__code').classList.add('qrblock__codeExt');
      document.querySelector('.qrblock').classList.add('qrblockExt');
      document.querySelector('.heading--white-mobile').classList.add('heading--white-mobileExt');
      document.querySelector('.page-content__background').classList.remove('page-content__background--qrcode');

      /*      
            $('#qrtext').hide();
            $('.qrblock__code').addClass('qrblock__codeExt');
            $('.qrblock').addClass('qrblockExt');
            $('.heading--white-mobile').addClass('heading--white-mobileExt');
            $('.page-content__background').removeClass('page-content__background--qrcode');
      */
      document.querySelector('.heading--margin-top-big').style.marginTop = '0';
    } else if ('qrcode' in ev) {
      document.querySelector("#qrtext").style.display = "block";
      document.querySelector('.qrblock__code').classList.remove('qrblock__codeExt');
      document.querySelector('.qrblock').classList.remove('qrblockExt');
      document.querySelector('.heading--white-mobile').classList.remove('heading--white-mobileExt');
      document.querySelector('.page-content__background').classList.add('page-content__background--qrcode');

      /*      
            $('#qrtext').show();
            $('.qrblock__code').removeClass('qrblock__codeExt');
            $('.qrblock').removeClass('qrblockExt');
            $('.heading--white-mobile').removeClass('heading--white-mobileExt');
            $('.page-content__background').addClass('page-content__background--qrcode');
      */
      document.querySelector('.heading--margin-top-big').style.marginTop = '50px';
    }
  } else {
    // self-hosted
    if ('button' in ev) {
      document.querySelector("#qrtext").style.display = "none";
      document.querySelector(".landingContent__codeHeading").style.display = "none";
      document.querySelector(".landingContent__code-qr").classList.add('qrblockExt');
      document.querySelector(".landingContent__code-container").classList.add('landingContent__code-containerExt');
      document.querySelector(".landingContent__text").style.display = "none";
      document.querySelector('.landingContent__text').style.display = "none";

      /*
            $('#qrtext').hide();
            $(".landingContent__codeHeading").hide();
            $('.landingContent__code-qr').addClass('qrblockExt');
            $('.landingContent__code-container').addClass('landingContent__code-containerExt');
      
            $('.landingContent__text').hide();
      */
    } else if ('qrcode' in ev) {
      document.querySelector("#qrtext").style.display = "block";
      document.querySelector(".landingContent__codeHeading").style.display = "flex";
      document.querySelector(".landingContent__code-qr").classList.remove('qrblockExt');
      document.querySelector(".landingContent__code-container").classList.remove('landingContent__code-containerExt');
      document.querySelector(".landingContent__text").style.display = "block";

      /*
            $('#qrtext').show();
            $(".landingContent__codeHeading").show();
            $('.landingContent__code-container').removeClass('landingContent__code-containerExt');
            $('.landingContent__code-qr').removeClass('qrblockExt');
      
            $('.landingContent__text').show();
      */
    }
  }
}
if (mobileDevice) {
  // $('#qrcode').addClass('qrtap');
  // $('.qr_code_instruction').html('Touch the QR code or scan it with <b>WWPass&nbsp;PassKey&nbsp;app</b>');
  // document.querySelector('#qrcode').classList.add('qrtap');

  if (document.querySelector('.qr_code_instruction')) {
    // pre-2019
    document.querySelector('.qr_code_instruction').innerHTML = 'Tap the QR code or scan it with <b>WWPass&nbsp;Key&nbsp;app</b> to open your PAssHub vault';
  }
} else {
  //  $(document).ready(() => {
  function checkPlugin() {
    if (wwpass_frontend__WEBPACK_IMPORTED_MODULE_0__.pluginPresent()) {
      // pre-2019 login (legacy)
      let hardwarePassKeySet = document.querySelectorAll('.hardware');
      if (hardwarePassKeySet.length) {
        [].forEach.call(hardwarePassKeySet, it => {
          it.classList.remove('hardware');
        });
        const infoShare = document.querySelector('.landingContent__infoShare');
        infoShare.classList.add('landingContent__infoShare--hardToken');
        return;
      }
      // biz login
      hardwarePassKeySet = document.querySelectorAll('.landingContent__hardToken');
      if (hardwarePassKeySet.length) {
        [].forEach.call(hardwarePassKeySet, it => {
          it.classList.remove('landingContent__hardToken');
        });
        return;
      }
      // login 2019
      /*
      const loginBtn = document.querySelector('#button--login');
      loginBtn.classList.remove('embedded--hide');
      $('#button--login > button').hide();
      return;
      */
    }
    setTimeout(checkPlugin, 100);
  }
  setTimeout(checkPlugin, 100);
  //  });
}

// login 2019

document.addEventListener('DOMContentLoaded', () => {
  const qrtext = document.querySelector('#qrtext');
  if (qrtext) {
    if (mobileDevice) {
      // qrtext.innerText = 'Tap the QR code or ';
      qrtext.innerHTML = 'Download <b>WWPass&nbsp;Key&nbsp;App</b> and scan&nbsp;or&nbsp;tap the QR&nbsp;code';
    } else {
      qrtext.innerHTML = 'Scan the QR code with WWPass™ Key App';
      // qrtext.classList.add('text--qrcode');
    }
    qrtext.style.display = 'block';
  }
  wwpass_frontend__WEBPACK_IMPORTED_MODULE_0__.authInit({
    qrcode: '#qrcode',
    mobileLoginExtraButtons: document.querySelectorAll(".signin-mobile"),
    passkey: document.querySelector('#button--login'),
    ticketURL: `${urlBase}getticket.php`,
    callbackURL: `${urlBase}login.php`,
    uiCallback,
    forcePasskeyButton: false,
    universal: true,
    fastForward: true
  });
});
})();

/******/ })()
;
//# sourceMappingURL=login.js.map
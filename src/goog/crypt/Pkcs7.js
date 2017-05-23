/**
 * @license
 * Copyright 2013 Google Inc. All rights reserved.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */


 // taken from https://17768337515975137919.googlegroups.com/attach/2289f55123597b/pkcs7.js?part=0.1&view=1&vt=ANaJVrFtvUgHozx__0pFjQn6aoP8-qVBLbf51hnRCoKOnA0Gd6iEAs780P1X2xqWU1Ot5lDkw0rrXMQ9KM20EaVYX-x1RdCJsnxx9L3Hi2k1cplP2Wlp-7g

goog.provide('goog.crypt.Pkcs7');

goog.require('goog.array');
//goog.require('goog.crypt.base64');

/**
 * The pkcs padding scheme.
 * The padding is of the following format:
 * {1}, {2, 2}, {3, 3, 3}, {4, 4, 4, 4}...
 * @constructor
 */
goog.crypt.Pkcs7 = function() { };

/**
 * Returns whether the number is a valid 'byte' (0-255 no decimals).
 * @param {number} b The number to test.
 * @return {boolean} If the send number is a byte.
 */
goog.crypt.Pkcs7.isByte = function(b) {
  return (typeof b == 'number' &&
      b >= 0 &&
      b <= 255 &&
      b - Math.floor(b) == 0);
};

/**
 * Verifies a given ByteArray is indeed made of bytes.
 * @param {!ByteArray} bytes The bytearray to test.
 * @return {boolean} If the array if a byteArray.
 */
goog.crypt.Pkcs7.isByteArray = function(bytes) {
  var yes = 1;
  for (var i = 0; i < bytes.length; i++) {
    yes &= goog.crypt.Pkcs7.isByte(bytes[i]) | 0;
  }
  return yes == 1;
};

/**
 * Does near constant time ByteArray comparison.
 * @param {!ByteArray} ba1 The first bytearray to check.
 * @param {!ByteArray} ba2 The second bytearray to check.
 * @return {boolean} If the array are equal.
 */
goog.crypt.Pkcs7.compareByteArray = function(ba1, ba2) {
  if (ba1.length !== ba2.length) {
    return false;
  }
  if (!goog.crypt.Pkcs7.isByteArray(ba1) || !goog.crypt.Pkcs7.isByteArray(ba2)) {
    return false;
  }
  var yes = 1;
  for (var i = 0; i < ba1.length; i++) {
    yes &= !(ba1[i] ^ ba2[i]) | 0;
  }
  return yes == 1;
};


/**
 * Encodes the given message according to PKCS7 as described in:
 * http://en.wikipedia.org/wiki/Padding_(cryptography)#PKCS7
 * @param {number} k The block size in bytes.
 * @param {!goog.crypt.base64.encodeByteArray} m The message to encode.
 * @return {!goog.crypt.base64.encodeByteArray} The encoded message.
 */
goog.crypt.Pkcs7.prototype.encode = function(k, m) {
  var n = k - (m.length % k);
  return m.concat(goog.array.repeat(n, n));
};


/**
 * Decodes the given message according to PKCS7 as described in:
 *     http://en.wikipedia.org/wiki/Padding_(cryptography)#PKCS7
 * @param {number} k The block size in bytes.
 * @param {!goog.crypt.base64.encodeByteArray} m The message to decode.
 * @return {?goog.crypt.base64.encodeByteArray} The decode message or null
 *     for invalid encoding messages.
 */
goog.crypt.Pkcs7.prototype.decode = function(k, m) {
  var length = m.length;
  var lastByte = m[m.length - 1];
  var error = 0;
  error |= (lastByte > length);
  error |= (lastByte > k);
  error |= (lastByte == 0);
  error |= (length % k != 0);
  var computedPadding = goog.array.repeat(lastByte, lastByte);
  var providedPadding = goog.array.slice(m, length - lastByte);
  error |= (!goog.crypt.Pkcs7.compareByteArray(
      computedPadding, providedPadding));
  if (error) {
    // TODO(user): Throw an exception here instead. b/16110945
    throw(new Error("Paddings don't match."));
  }
  return goog.array.slice(m, 0, length - lastByte);
};

/* Common definitions
   Copyright 2017 The NeoPG developers

   NeoPG is released under the Simplified BSD License (see license.txt)
*/

#pragma once

#define NEOPG_DLL __attribute__((visibility("default")))

/**
 * Interfaces annotated with this API are stable and supported.
 * @param maj The major version for the initial release of this API.
 * @param min The minor version for the initial release of this API.
 */
#define NEOPG_PUBLIC_API(maj, min) NEOPG_DLL

/**
 * Interfaces annotated with this API are supported, but they are
 * experimental and can change in incompatible ways.
 */
#define NEOPG_UNSTABLE_API NEOPG_DLL

/**
 * Interfaces annotated with this API are only exported for internal
 * reasons, and should not be used otherwise.
 */
#define NEOPG_TEST_API NEOPG_DLL

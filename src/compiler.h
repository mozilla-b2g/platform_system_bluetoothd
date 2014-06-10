/*
 * Copyright (C) 2014  Mozilla Foundation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#pragma once

/*
 * The macro 'ATTRIBS' declares compiler-specific attributes in a
 * generic way. To use function-argument attributes specify
 *
 *  ATTRIBS(comma-separated-list-of-attributes)
 *
 * after the function argument. Unsupported attributes will remain
 * empty
 */
#ifdef __GNUC__
#define ATTRIBS(_attrs) __attribute__(( _attrs ))
#else
#define ATTRIBS(_attrs)
#endif

/* 'UNUSED' marks a function argument as not used. */
#ifdef __GNUC__
#define UNUSED  __unused__
#else
#define UNUSED
#endif

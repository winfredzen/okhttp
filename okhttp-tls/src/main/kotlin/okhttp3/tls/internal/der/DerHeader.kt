/*
 * Copyright (C) 2020 Square, Inc.
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
package okhttp3.tls.internal.der

internal data class DerHeader(
  /** Bits 7,8. 00=Universal, 01=Application, 10=Context-Specific, 11=Private */
  var tagClass: Int = -1,

  var tag: Long = -1L,

  /** Bit 6. 0=Primitive, 1=Constructed */
  var constructed: Boolean = false,

  var length: Long = -1L
)

/*
 * Copyright 2017-present Open Networking Foundation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.onosproject.incubator.net.osdf.abstractactions;

/**
 * High level operations list.
 */
public enum ActionList {
    /**
     * Routing a traffic inside a region (intra-site-routing).
     */

    INTRA_ROUTE,

    /**
     * Routing a traffic between regions (inter-site-routing).
     */
    INTER_ROUTE,


}

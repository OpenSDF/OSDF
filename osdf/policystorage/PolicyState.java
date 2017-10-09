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

package org.onosproject.incubator.net.osdf.policystorage;

/**
 * Policy states.
 */
public enum PolicyState {
    /**
     * Signifies that a policy is to be installed or reinstalled.
     */
    INSTALL_REQ,

    /**
     * Signifies that a policy has been successfully installed.
     */
    INSTALLED,

    /**
     * Signifies that a policy has failed compilation and that it cannot
     * be satisfied by the network at this time.
     */
    FAILED,

    /**
     * Signifies that a policy will be withdrawn.
     */
    WITHDRAW_REQ,

    /**
     * Signifies that a policy has been withdrawn from the system.
     */
    WITHDRAWN,

    /**
     * Signifies that a policy has failed installation or withdrawal, but
     * still hold some or all of its resources.
     * (e.g. link reservations, flow rules on the data plane, etc.)
     */
    CORRUPT,

    /**
     * Signifies that a policy has been purged from the system.
     */
    PURGED
}

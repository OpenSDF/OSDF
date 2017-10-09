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

import org.onosproject.event.AbstractEvent;
import org.onosproject.incubator.net.osdf.policies.Policy;

import java.util.Optional;

/**
 * Status of a policy.
 */
public class PolicyEvent extends AbstractEvent<PolicyEvent.Type, Policy> {


    public PolicyEvent(Type type, Policy subject, long time) {
        super(type, subject, time);
    }


    public PolicyEvent(Type type, Policy subject) {
        super(type, subject);
    }

    public static Optional<PolicyEvent> getEvent(Policy policy) {
        return getEvent(policy.getPolicyState(), policy);
    }

    public static Optional<PolicyEvent> getEvent(PolicyState state, Policy policy) {
        Type type;
        switch (state) {
            case INSTALL_REQ:
                type = Type.INSTALL_REQ;
                break;
            case INSTALLED:
                type = Type.INSTALLED;
                break;
            case WITHDRAW_REQ:
                type = Type.WITHDRAW_REQ;
                break;
            case WITHDRAWN:
                type = Type.WITHDRAWN;
                break;
            case FAILED:
                type = Type.FAILED;
                break;
            case CORRUPT:
                type = Type.CORRUPT;
                break;
            case PURGED:
                type = Type.PURGED;
                break;

            default:
                return Optional.empty();
        }
        return Optional.of(new PolicyEvent(type, policy));
    }

    public enum Type {
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

}

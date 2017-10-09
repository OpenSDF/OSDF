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

package org.onosproject.incubator.net.osdf.policies;

/**
 * Policy identifier interface.
 */
public interface PolicyIdInterface {
    /**
     * Returns a policyId.
     *
     * @return PolicyIdInterface
     */
    int getPolicyId();


    /**
     * Returns a Policy name.
     *
     * @return PolicyName
     */
    String getPolicyName();


    /**
     * Creates a policy Id based on a given name.
     *
     * @param policyName policy name
     */
    void createPolicyId(String policyName);

}

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

import com.google.common.collect.Multimap;
import org.onosproject.event.ListenerService;
import org.onosproject.incubator.net.osdf.policies.DefaultPolicyId;
import org.onosproject.incubator.net.osdf.policies.Policy;
import org.onosproject.net.flow.DefaultFlowRule;

import java.util.Collection;
import java.util.Map;

/**
 * Policy service interface.
 */
public interface PolicyService extends ListenerService<PolicyEvent, PolicyListener> {

    Iterable<Policy> getPolicies();

    void addPending(Policy policy);

    Iterable<Policy> getPendingPolicies();


    void addCurrent(Policy policy);


    Iterable<Policy> getCurrentPolicies();

    void addFlowRule(Policy policy, DefaultFlowRule flowRule);

    void removeCurrentPolicy(Policy policy);

    Policy getPolicy(String policyId);

    Map<DefaultPolicyId, Policy> getCurrentPolicyMap();

    int getRulesCount(Policy policy);

    Multimap<DefaultPolicyId, DefaultFlowRule> getFlowRulesList();


    Collection<DefaultFlowRule> getFlowRulesForPolicy(Policy policy);


}

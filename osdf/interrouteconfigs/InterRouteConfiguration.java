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

package org.onosproject.incubator.net.osdf.interrouteconfigs;


import com.google.common.collect.Maps;
import com.googlecode.concurrenttrees.radix.node.concrete.DefaultByteArrayNodeFactory;
import com.googlecode.concurrenttrees.radixinverted.ConcurrentInvertedRadixTree;
import com.googlecode.concurrenttrees.radixinverted.InvertedRadixTree;
import org.apache.felix.scr.annotations.Activate;
import org.apache.felix.scr.annotations.Component;
import org.apache.felix.scr.annotations.Deactivate;
import org.apache.felix.scr.annotations.Reference;
import org.apache.felix.scr.annotations.ReferenceCardinality;
import org.apache.felix.scr.annotations.Service;
import org.onlab.packet.Ip4Address;
import org.onlab.packet.Ip6Address;
import org.onlab.packet.IpAddress;
import org.onlab.packet.IpPrefix;
import org.onlab.packet.MacAddress;
import org.onosproject.core.ApplicationId;
import org.onosproject.core.CoreService;
import org.onosproject.net.config.ConfigFactory;
import org.onosproject.net.config.NetworkConfigEvent;
import org.onosproject.net.config.NetworkConfigListener;
import org.onosproject.net.config.NetworkConfigRegistry;
import org.onosproject.net.config.NetworkConfigService;
import org.onosproject.net.config.basics.SubjectFactories;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.HashSet;
import java.util.Map;
import java.util.Set;


/**
 * An implementation of inter-site-routing configuration service.
 */
@Component(immediate = true)
@Service
public class InterRouteConfiguration implements InterRouteConfigurationService {


    private final Logger log = LoggerFactory.getLogger(getClass());
    private final Map<String, String> ipPrefixRegionMap4 = Maps.newConcurrentMap();
    private final Map<String, String> ipPrefixRegionMap6 = Maps.newConcurrentMap();

    private final InternalNetworkConfigListener configListener =
            new InternalNetworkConfigListener();
    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    protected NetworkConfigRegistry registry;
    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    protected NetworkConfigService configService;
    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    protected CoreService coreService;


    private Set<IpAddress> gatewayIpAddresses = new HashSet<>();
    private InvertedRadixTree<LocalIpPrefixEntry>
            localPrefixTable4 = new ConcurrentInvertedRadixTree<>(
            new DefaultByteArrayNodeFactory());
    private InvertedRadixTree<LocalIpPrefixEntry>
            localPrefixTable6 = new ConcurrentInvertedRadixTree<>(
            new DefaultByteArrayNodeFactory());
    private MacAddress virtualGatewayMacAddress;
    private ConfigFactory<ApplicationId, InterRouteConfig>
            interRouteConfigConfigFactory =
            new ConfigFactory<ApplicationId, InterRouteConfig>(
                    SubjectFactories.APP_SUBJECT_FACTORY,
                    InterRouteConfig.class, "InterRouting") {
                @Override
                public InterRouteConfig createConfig() {
                    log.info("Create a new Inter Route Config");
                    return new InterRouteConfig();
                }
            };

    public static String createBinaryString(IpPrefix ipPrefix) {
        byte[] octets = ipPrefix.address().toOctets();
        StringBuilder result = new StringBuilder(ipPrefix.prefixLength());
        result.append("0");
        for (int i = 0; i < ipPrefix.prefixLength(); i++) {
            int byteOffset = i / Byte.SIZE;
            int bitOffset = i % Byte.SIZE;
            int mask = 1 << (Byte.SIZE - 1 - bitOffset);
            byte value = octets[byteOffset];
            boolean isSet = ((value & mask) != 0);
            result.append(isSet ? "1" : "0");
        }
        return result.toString();
    }

    @Activate
    public void activate() {
        configService.addListener(configListener);
        registry.registerConfigFactory(interRouteConfigConfigFactory);
        setUpConfiguration();
        log.info("Inter routing configuration service started");
    }

    @Deactivate
    public void deactivate() {
        registry.unregisterConfigFactory(interRouteConfigConfigFactory);
        configService.removeListener(configListener);
        log.info("inter routing configuration service stopped");
    }

    /**
     * Set up routing information from configuration.
     */


    private void setUpConfiguration() {


        InterRouteConfig config = configService.getConfig(
                coreService.registerApplication(InterRouteConfigurationService
                        .INTER_ROUTING_APP_ID), InterRouteConfigurationService.CONFIG_CLASS);


        if (config == null) {
            log.warn("No inter routing config available!");
            return;
        }


        for (LocalIpPrefixEntry entry : config.localIp4PrefixEntries()) {
            localPrefixTable4.put(createBinaryString(entry.ipPrefix()), entry);
            gatewayIpAddresses.add(entry.getGatewayIpAddress());
            ipPrefixRegionMap4.put(createBinaryString(entry.ipPrefix()), entry.getRegion());


        }
        for (LocalIpPrefixEntry entry : config.localIp6PrefixEntries()) {
            localPrefixTable6.put(createBinaryString(entry.ipPrefix()), entry);
            gatewayIpAddresses.add(entry.getGatewayIpAddress());
            ipPrefixRegionMap6.put(createBinaryString(entry.ipPrefix()), entry.getRegion());

        }

        virtualGatewayMacAddress = config.virtualGatewayMacAddress();


    }

    /**
     * Evaluates whether an IP address belongs to local SDN network.
     *
     * @param ipAddress the IP address to evaluate
     * @return boolean value
     */
    @Override
    public boolean isIpAddressLocal(IpAddress ipAddress) {
        if (ipAddress.isIp4()) {

            return localPrefixTable4.getValuesForKeysPrefixing(
                    createBinaryString(
                            IpPrefix.valueOf(ipAddress, Ip4Address.BIT_LENGTH)))
                    .iterator().hasNext();
        } else {
            return localPrefixTable6.getValuesForKeysPrefixing(
                    createBinaryString(
                            IpPrefix.valueOf(ipAddress, Ip6Address.BIT_LENGTH)))
                    .iterator().hasNext();
        }
    }

    /**
     * Evaluates whether an IP prefix belongs to local SDN network.
     *
     * @param ipPrefix the IP prefix to evaluate.
     * @return true if the IP prefix belongs to local SDN network, otherwise false.
     */
    @Override
    public boolean isIpPrefixLocal(IpPrefix ipPrefix) {
        return (localPrefixTable4.getValueForExactKey(
                createBinaryString(ipPrefix)) != null ||
                localPrefixTable6.getValueForExactKey(
                        createBinaryString(ipPrefix)) != null);


    }

    /**
     * Returns the region ID based on given IP prefix.
     *
     * @param ipPrefix ip prefix
     * @return region ID
     */
    @Override
    public String getRegion(IpPrefix ipPrefix) {

        return ipPrefixRegionMap4.get(createBinaryString(ipPrefix));

    }

    @Override
    public int getPrefixLen(IpPrefix ipPrefix) {
        return ipPrefix.prefixLength();
    }


    /**
     * Evaluates whether an IP address is a virtual gateway IP address.
     *
     * @param ipAddress the IP address to evaluate
     * @return true if the IP address is a virtual gateway address, otherwise false
     */
    @Override
    public boolean isVirtualGatewayIpAddress(IpAddress ipAddress) {

        return gatewayIpAddresses.contains(ipAddress);
    }

    /**
     * Returns virtual gateway MAC address.
     *
     * @return virtual gateway MAC address
     */
    @Override
    public MacAddress getVirtualGatewayMacAddress() {

        return virtualGatewayMacAddress;
    }


    /**
     * A local implementation of network config listener to handle
     * configuration events.
     */
    private class InternalNetworkConfigListener implements NetworkConfigListener {
        @Override
        public void event(NetworkConfigEvent event) {
            switch (event.type()) {
                case CONFIG_REGISTERED:
                    log.info("config registered");
                    break;
                case CONFIG_UNREGISTERED:
                    break;
                case CONFIG_ADDED:
                case CONFIG_UPDATED:
                case CONFIG_REMOVED:
                    if (event.configClass() == InterRouteConfigurationService.CONFIG_CLASS) {
                        setUpConfiguration();
                    }
                    break;
                default:
                    break;
            }
        }
    }


}

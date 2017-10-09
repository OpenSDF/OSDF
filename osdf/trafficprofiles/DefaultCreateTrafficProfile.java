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

package org.onosproject.incubator.net.osdf.trafficprofiles;

import org.apache.felix.scr.annotations.Deactivate;
import org.apache.felix.scr.annotations.Service;
import org.onosproject.incubator.net.osdf.applicationinfo.ApplicationTypes;
import org.onosproject.incubator.net.osdf.applicationinfo.TrafficClasses;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;

import java.util.logging.Logger;

/**
 * An implementation of CreateTrafficProfile interface.
 */
@Component(immediate = true)
@Service
public class DefaultCreateTrafficProfile implements CreateTrafficProfile {

    private final Logger log = Logger.getLogger(getClass().getName());
    private DefaultTrafficProfile trafficProfile;


    @Activate
    public void activate() {
        log.info("Started");
        trafficProfile = null;

    }

    @Deactivate
    public void deactivate() {
        log.info("Stopped");

    }

    /**
     * Returns a traffic Profile.
     *
     * @return a traffic profile
     */
    public TrafficProfile getTrafficProfile() {
        return trafficProfile;
    }


    /**
     * <p>
     * Creates a traffic profile instance based
     * on application type and traffic profile id.
     *
     * @param applicationType  Type of an application
     * @param trafficProfileId Traffic profile identifier
     */
    public void createTrafficProfile(String applicationType, String trafficProfileId) {
        DefaultTrafficProfileId trafficProfileIds;
        TrafficClasses trafficClass = null;
        ApplicationTypes applicationTypes = null;


        trafficProfileIds = new DefaultTrafficProfileId(trafficProfileId);

        switch (applicationType) {
            case "WEB":
                applicationTypes = ApplicationTypes.WEB;
                trafficClass = ApplicationTypes.WEB.getTrafficClass();
                break;
            case "VOIP":
                applicationTypes = ApplicationTypes.VOIP;
                trafficClass = ApplicationTypes.VOIP.getTrafficClass();
                break;
            case "PING":
                applicationTypes = ApplicationTypes.PING;
                trafficClass = ApplicationTypes.PING.getTrafficClass();
                break;
            case "VIDEO_STREAMING":
                applicationTypes = ApplicationTypes.VIDEO_STREAMING;
                trafficClass = ApplicationTypes.VIDEO_STREAMING.getTrafficClass();
                break;
            default:
                break;
        }

        trafficProfile = DefaultTrafficProfile
                .builder()
                .trafficProfileId(trafficProfileIds)
                .applicationType(applicationTypes)
                .trafficClass(trafficClass)
                .build();

    }

}

/**
* Copyright 2016-2018 F5 Networks, Inc.
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

'use strict';

/* eslint-disable no-underscore-dangle */

const util = require('util');
const q = require('q');
const pkgcloud = require('pkgcloud');

const AbstractAutoscaleProvider = require('@f5devcentral/f5-cloud-libs').autoscaleProvider;
const BigIp = require('@f5devcentral/f5-cloud-libs').bigIp;
const Logger = require('@f5devcentral/f5-cloud-libs').logger;
const cloudUtil = require('@f5devcentral/f5-cloud-libs').util;
const httpUtil = require('@f5devcentral/f5-cloud-libs').httpUtil;

let logger;

util.inherits(OpenStackAutoscaleProvider, AbstractAutoscaleProvider);

/**
* Constructor.
* @class
* @classdesc
* Openstack cloud provider implementation.
*
* @param {Object} [options]               - Options for the instance.
* @param {Object} [options.clOptions]     - Command line options if called from a script.
* @param {Object} [options.logger]        - Logger to use. Or, pass loggerOptions to get your own logger.
* @param {Object} [options.loggerOptions] - Options for the logger.
*                                           See {@link module:logger.getLogger} for details.
*/
function OpenStackAutoscaleProvider(options) {
    OpenStackAutoscaleProvider.super_.call(this, options);

    const loggerOptions = options ? options.loggerOptions : undefined;

    logger = options ? options.logger : undefined;

    if (logger) {
        this.logger = logger;
        cloudUtil.setLogger(logger);
    } else if (loggerOptions) {
        loggerOptions.module = module;
        logger = Logger.getLogger(loggerOptions);
        cloudUtil.setLoggerOptions(loggerOptions);
        this.logger = logger;
    } else {
        // use super's logger
        logger = this.logger;
        cloudUtil.setLogger(logger);
    }
}

/**
* Initialize class
*
* @param {Object} providerOptions                       - Provider-specific options.
* @param {String} providerOptions.instanceMetadataUrl   - Config Drive path or URL to retrieve
*                                                         metadata for the instance
* @param {String} providerOptions.autoscaleMetadataUrl  - URL to retrieve metadata autoscale metadata
* @param {String} providerOptions.autoscaleGroupTag     - Resource group name.
* @param {String} providerOptions.osCredentialsUrl      - Openstack credentials url.
*                                                         Required if not passing osCredentials
* @param {String} providerOptions.osCredentials         - Openstack credentials object.
*                                                         Required if not passing osCredentialsUrl
*         Credentials JSON object should have the following properties:
*         {
*             username:             <String> - Openstack username (required)
*             password:             <String> - Openstack password (required)
*             region:               <String> - Openstack region (optional, defaults to regionOne)
*             authURL:              <String> - Openstack identity service endpoint (required)
*             authVersion:          <String> - Openstack identity service version  (optional, defaults to v2)
*             domainId:             <String> - Openstack user domain id (optional)
*             domainName:           <String> - Openstack user domain name (optional)
*         }
* @returns {Promise} A promise which will be resolved when init is complete.
*/
OpenStackAutoscaleProvider.prototype.init = function init(providerOptions) {
    let credentialsJson;

    this.logger.silly('providerOptions:', providerOptions);
    this.autoscaleGroupTag = providerOptions.autoscaleGroupTag;
    this.instanceMetadataUrl = providerOptions.instanceMetadataUrl;
    this.autoscaleMetadataResource = providerOptions.autoscaleMetadataResource;
    this.autoscaleMetadataResourcePutUrl = providerOptions.autoscaleMetadataUrl.replace('\\&', '&');
    this.autoscaleMetadataResourceGetUrl = '';
    this.autoscaleStack = providerOptions.autoscaleStack;

    this.bigIp = new BigIp({ loggerOptions: this.loggerOptions });
    return this.bigIp.init(
        'localhost',
        this.clOptions.user,
        this.clOptions.password || this.clOptions.passwordUrl,
        {
            port: this.clOptions.port,
            passwordIsUrl: typeof this.clOptions.passwordUrl !== 'undefined'
        }
    )
        .then(() => {
            if (providerOptions.osCredentialsUrl) {
                return cloudUtil.getDataFromUrl(providerOptions.osCredentialsUrl);
            }
            return q();
        })
        .then((data) => {
            if (providerOptions.osCredentialsUrl) {
                credentialsJson = JSON.parse(data);
            } else {
                credentialsJson = providerOptions.osCredentials;
            }

            const clientOpts = {
                provider: 'openstack',
                username: credentialsJson.username,
                password: credentialsJson.password,
                // default for DevStack, might be different on other OpenStack distributions
                region: credentialsJson.region || 'regionOne',
                authUrl: credentialsJson.authUrl,
                keystoneAuthVersion: credentialsJson.authVersion,
                domainId: credentialsJson.domainId,
                domainName: credentialsJson.domainName
            };

            this.logger.silly('clientOptions:', clientOpts);
            this.osComputeClient = pkgcloud.compute.createClient(clientOpts);
            this.osOrchClient = pkgcloud.orchestration.createClient(clientOpts);

            return getAutoscaleMetadataStackResourceUrl(
                this.osOrchClient,
                this.autoscaleStack,
                this.autoscaleMetadataResource
            );
        })
        .then((url) => {
            this.autoscaleMetadataResourceGetUrl = url;

            return getAutoscaleMetadataStackResource(
                this.autoscaleMetadataResourceGetUrl,
                this.osOrchClient._identity.token.id
            );
        })
        .then((autoscaleResource) => {
            if (
                autoscaleResource.attributes.data === 'null' ||
                autoscaleResource.attributes.data[1] === 'null'
            ) {
                // initialize autoscale metadata resource if data is null/empty
                // data would also be null if the body sent to the endpoint is malformed
                // (request doesn't error out) this should only happen with the first
                // instance in the autoscale group with current implementation, signal
                // handle does not need token for PUT
                const payload = {
                    data: { status: 'INIT' }
                };

                const initBody = JSON.stringify(payload);
                const headers = {
                    'Content-Type': 'application/json'
                };

                const url = this.autoscaleMetadataResourcePutUrl;

                logger.debug('Initializing autoscale metadata resource', initBody);

                return httpUtil.put(url, { headers, body: payload })
                    .then((res) => {
                        logger.debug(`Initialized autoscale metadata. ${res}`);
                        return q();
                    })
                    .catch((err) => {
                        // eslint-disable-next-line max-len
                        const message = `ERROR: Unable to initialize autoscale metadata resource. Details: ${err}`;
                        logger.error(message);
                        return q.reject(new Error(message));
                    });
            }

            const logMessage = autoscaleResource.attributes.data.status === 'INIT' ?
                'Autoscale resource has already been initialized.' :
                `Autoscale resource data found: ${autoscaleResource.attributes.data}`;
            logger.silly(logMessage);
            return q();
        })
        .catch((err) => {
            logger.error('Error encountered while initializing provider. Details: \n', err);
            return q.reject(err);
        });
};

/**
* Gets the instance ID of this instance
*
* @returns {Promise} A promise which will be resolved with the instance ID of this instance
*                    or rejected if an error occurs.
*/
OpenStackAutoscaleProvider.prototype.getInstanceId = function getInstanceId() {
    const deferred = q.defer();
    let logMessage;

    if (!this.instanceId) {
        // Get our instance info from metadata - can be from url or config drive
        getInstanceMetadata(this.instanceMetadataUrl)
            .then((instanceData) => {
                this.logger.silly('instance data:', instanceData);

                if (instanceData) {
                    if (instanceData.uuid) {
                        this.instanceId = instanceData.uuid;
                        deferred.resolve(this.instanceId);
                    } else {
                        logger.warn('No instance uuid in meta data. Attempting to find by instance name.');
                        if (instanceData.name) {
                            const instanceName = instanceData.name;
                            getTaggedInstances(this.osComputeClient, this.autoscaleGroupTag)
                                .then((results) => {
                                    const vmIds = Object.keys(results);
                                    for (let i = 0; i < vmIds.length; i++) {
                                        const vmId = vmIds[i];
                                        if (results[vmId].instanceName === instanceName) {
                                            this.instanceId = results[vmId].id;
                                            break;
                                        }
                                    }

                                    if (this.instanceId) {
                                        deferred.resolve(this.instanceId);
                                    } else {
                                        logMessage = 'Unable to determine instance ID by name lookup.';
                                        deferred.reject(new Error(logMessage));
                                    }
                                });
                        } else {
                            logMessage = 'Unable to retrieve instance name to use for id lookup.';
                            deferred.reject(new Error(logMessage));
                        }
                    }
                } else {
                    logMessage = 'Unable to retrieve metadata.';
                    deferred.reject(new Error(logMessage));
                }
            })
            .catch((err) => {
                logger.error('Error encountered while getting instance id. Details: \n', err);
                deferred.reject(err);
            });
    } else {
        deferred.resolve(this.instanceId);
    }

    return deferred.promise;
};

/**
* Gets info for instances that belong to the autoscaling group.
*
* @returns {Promise} A promise which will be resolved with a dictionary of instances keyed by instanceID.
*                    Each instance value should have the following properties, (at minimum):
*                   {
*                       isMaster: <Boolean>,
*                       hostname: <String>,
*                       mgmtIp: <String>,
*                       privateIp: <String>
*                       providerVisible: <Boolean> (does the cloud provider know about this instance)
*                   }
*/
OpenStackAutoscaleProvider.prototype.getInstances = function getInstances() {
    const deferred = q.defer();
    const idsToDelete = [];
    const instancesToRevoke = [];

    let registeredInstances = {};
    let instancesToReturn = {};
    let vmsWithAutoscaleTag;

    getTaggedInstances(this.osComputeClient, this.autoscaleGroupTag)
        .then((results) => {
            vmsWithAutoscaleTag = results;
            instancesToReturn = vmsWithAutoscaleTag;
            return getRegisteredInstances(this.osOrchClient, this.autoscaleMetadataResourceGetUrl, false);
        })
        .then((getResult) => {
            registeredInstances = getResult;
            logger.debug('Populating autoscale instances list.');
            const registeredInstanceIds = registeredInstances ? Object.keys(registeredInstances) : [];
            if (registeredInstanceIds.length > 0) {
                logger.debug('Consolidating registered instances and tagged instances');
                let instanceId;
                let instance;

                const isValidInstance = function (id, instanceToCheck) {
                    let isValid = false;
                    if (vmsWithAutoscaleTag[id] !== undefined) {
                        if (instanceToCheck.isMaster) {
                            isValid = !this.isInstanceExpired(instanceToCheck);
                        } else {
                            isValid = true;
                        }
                    }
                    return isValid;
                };

                for (let i = 0; i < registeredInstanceIds.length; ++i) {
                    instanceId = registeredInstanceIds[i];
                    instance = registeredInstances[instanceId];
                    if (isValidInstance.call(this, instanceId, instance)) {
                        const providerVisible = vmsWithAutoscaleTag[instanceId] ?
                            vmsWithAutoscaleTag[instanceId].providerVisible :
                            false;
                        instancesToReturn[instanceId] = instance;
                        instancesToReturn[instanceId].providerVisible = providerVisible;
                        logger.silly('Valid instance: ', instanceId);
                    } else {
                        logger.silly('Invalid instance: ', instanceId);
                        // Get a list of non-master instances that are registered but Openstack
                        // does not know about or masters that are expired and delete them
                        idsToDelete.push(instanceId);

                        // if we're using BIG-IQ for licensing, revoke the licenses
                        // of the deleted BIG-IPs
                        if (this.clOptions.licensePool) {
                            instancesToRevoke.push(instance);
                        }
                    }
                }
            } else {
                logger.debug('No instances in the registered instances list. Returning tagged instances');
                instancesToReturn = vmsWithAutoscaleTag;
            }
        })
        .then(() => {
            // TODO: if hostnames are not assigned
            if (idsToDelete.length > 0) {
                logger.debug(
                    'Deleting instances that are not known to OpenStack or in invalid state', idsToDelete
                );
                return deregisterInstances(
                    this.osOrchClient,
                    this.autoscaleMetadataResourcePutUrl,
                    idsToDelete,
                    registeredInstances
                );
            }
            return q();
        })
        .then(() => {
            if (instancesToRevoke.length > 0) {
                logger.debug('Revoking licenses of non-masters that are not known to OpenStack');
                return this.revokeLicenses(instancesToRevoke, { bigIp: this.bigIp });
            }
            return q();
        })
        .then(() => {
            deferred.resolve(instancesToReturn);
        })
        .catch((err) => {
            logger.error('Error encountered while getting instances. Details: \n', err);
            deferred.reject(err);
        });

    return deferred.promise;
};


/**
* Elects a new master instance from the available instances
*
* @param {Object} instances - Dictionary of instances as returned by getInstances
*
* @returns {Promise} A promise which will be resolved with the instance ID of the
*                    elected master.
*/
OpenStackAutoscaleProvider.prototype.electMaster = function electMaster(instances) {
    const instanceIds = Object.keys(instances);
    let oldest = new Date();
    let masterId;
    let masterFound = false;

    if (instanceIds.length === 0) {
        return q.reject(new Error('Error while electing master: No instances found.'));
    }

    instanceIds.forEach((instanceId) => {
        logger.silly('Checking if this instance can become master:', instances[instanceId]);
        // select the oldest instance
        if (
            instances[instanceId].providerVisible &&
            Date.parse(instances[instanceId].created) < Date.parse(oldest)
        ) {
            oldest = instances[instanceId].created;
            masterId = instanceId;
            masterFound = true;
        }
    });

    if (masterFound) {
        return q(masterId);
    }
    return q.reject(new Error('Error while electing master: No possible master found.'));
};

/**
* Called to retrieve master instance credentials
*
* When joining a cluster we need the username and password for the
* master instance.
*
* Management IP and port can be optionally passed in so that credentials can be
* validated if desired.
*
* @param {String} mgmtIp - Management IP of master
* @param {String} port - Management port of master
*
* @returns {Promise} A promise which will be resolved with:
*                    {
*                        username: <admin_user>,
*                        password: <admin_password>
*                    }
*/
OpenStackAutoscaleProvider.prototype.getMasterCredentials = function getMasterCredentials() {
    return q({
        username: this.bigIp.user,
        password: this.bigIp.password
    });
};

/**
* Determines if a given instanceId is a valid master
*
* @param {String} instanceId - Instance ID to validate as a valid master.
* @param {Object} instances - Dictionary of instances as returned by getInstances.
*
* @returns {Promise} A promise which will be resolved with a boolean indicating
*                    wether or not the given instanceId is a valid master.
*/
OpenStackAutoscaleProvider.prototype.isValidMaster = function isValidMaster(instanceId, instances) {
    const possibleMaster = instances[instanceId];
    let bigIp;

    logger.debug('Checking if valid master.');
    logger.silly('isValidMaster called with instanceId: ', instanceId, ' instances:', instances);

    if (possibleMaster.providerVisible) {
        // get the password for this autoscale group
        return (
            this.clOptions.password ?
                q(this.clOptions.password) : cloudUtil.getDataFromUrl(this.clOptions.passwordUrl)
        )
            .then((bigIpPassword) => {
                // Compare instance's hostname to our hostname
                bigIp = new BigIp({ loggerOptions: this.loggerOptions });
                return bigIp.init(
                    possibleMaster.privateIp,
                    this.clOptions.user,
                    bigIpPassword,
                    {
                        port: this.clOptions.port
                    }
                );
            })
            .then(() => {
                return bigIp.list('/tm/sys/global-settings', null, cloudUtil.SHORT_RETRY);
            })
            .then((response) => {
                const actualHostname = response.hostname;
                let isValid = true;

                logger.silly(
                    'possibleMaster.hostname:',
                    possibleMaster.hostname,
                    ', actualHostname:',
                    actualHostname
                );

                if (possibleMaster.hostname !== actualHostname) {
                    logger.debug(
                        'Master not valid: hostname of possible master (',
                        possibleMaster.hostname,
                        ') does not match actual hostname (',
                        actualHostname, ')'
                    );
                    isValid = false;
                }

                return isValid;
            });
    }

    logger.debug('Master not valid: Instance is not visible.');
    return false;
};

/**
* Called when a master has been elected. Handles instance updates such as isMaster flag.
*
* @param {String} masterId - The instanceID that was elected master.
*
* @returns {Promise} A promise which will be resolved when processing is complete.
*/
OpenStackAutoscaleProvider.prototype.masterElected = function masterElected(masterId) {
    const deferred = q.defer();
    let updatedInstances = {
        // instances container, required by the openstack resource
        data: {}
    };
    // Find other instances that are marked as master, and mark them as non-master
    return getRegisteredInstances(this.osOrchClient, this.autoscaleMetadataResourceGetUrl, false)
        .then((registeredInstances) => {
            updatedInstances = registeredInstances;

            const registeredInstanceIds = Object.keys(registeredInstances);
            let instance;

            registeredInstanceIds.forEach((registeredId) => {
                instance = registeredInstances[registeredId];
                if (registeredId !== masterId && instance.isMaster) {
                    logger.silly(`Updating instance.isMaster for: ${registeredId}`);
                    instance.isMaster = false;
                    updatedInstances[registeredId] = instance;
                }
            });
            updateRegisteredInstances(
                this.orchClient,
                updatedInstances,
                this.autoscaleMetadataResourcePutUrl
            );
        })
        .then((success) => {
            logger.silly('Successfully updated registered instances after master election.');
            deferred.resolve(success);
        }, (error) => {
            const message = `ERROR: Unable to update registered instances after master election: ${error}`;
            logger.debug(message);
            deferred.reject(new Error(message));
        });
};

/**
* Saves the instance info
*
* @param {String} instanceId - ID of instance
* @param {Object} instance   - Latest instance data
*
* @returns {Promise} A promise which will be resolved with instance info.
*/
OpenStackAutoscaleProvider.prototype.putInstance = function putInstance(instanceId, instance) {
    logger.silly('Sending autoscale metadata to:', this.autoscaleMetadataResourcePutUrl);
    const instanceToPut = instance;

    // getRegisteredInstances ensure that instancesData is latest
    return getRegisteredInstances(this.osOrchClient, this.autoscaleMetadataResourceGetUrl, false)
        .then((result) => {
            logger.silly('Adding/Updating instance: ', instanceId);
            const instances = result;
            instanceToPut.lastUpdate = new Date();
            instances[instanceId] = instanceToPut;

            return updateRegisteredInstances(
                this.osOrchClient,
                instances,
                this.autoscaleMetadataResourcePutUrl
            );
        });
};

/**
* Gets all vms with specified Autoscale Tag from the servers list
*
* @param {Object} computeClient         - OpenStack compute client
* @param {String} autoscaleGroupTag     - Tag value of the autoscale group
*
* @returns {Promise} Promise which will be resolved with a dictionary of vmsWithAutoscaleTag
*                    keyed by the instance ID.
*                    Each vm object is created by parsing instance info returned from getServers.
*                    Each instance value should have the following properties, (at minimum):
*                   {
*                       isMaster: <Boolean>,
*                       hostname: <String>,
*                       mgmtIp: <String>,
*                       privateIp: <String>
*                       providerVisible: <Boolean> (does the cloud provider know about this instance)
*                   }
*/
function getTaggedInstances(computeClient, autoscaleGroupTag) {
    const deferred = q.defer();
    const vmsWithAutoscaleTag = {};

    logger.debug(`Getting instances with autoscale group tag [${autoscaleGroupTag}]`);

    computeClient.getServers((err, results) => {
        if (err) {
            logger.error('Error encountered while retrieving server list. Details: ', err);
            deferred.reject(err);
        } else {
            results.forEach((vm) => {
                if (vm.metadata.autoscale_group_tag === autoscaleGroupTag) {
                    // return only subset of properties
                    const vmInfo = {
                        id: vm.id,
                        mgmtIp: vm.metadata.management_ip,
                        privateIp: vm.metadata.config_sync_ip,
                        // extra props for debugging/troubleshooting
                        instanceName: vm.name,
                        metadata: vm.metadata,
                        links: vm.links,
                        created: vm.created,
                        novaStatus: vm.status,
                        osStatus: vm.openstack.status
                    };

                    // TODO: figure out other status like RESCUE etc,
                    if (
                        vm.status === 'ACTIVE' ||
                        vm.status === 'RUNNING' ||
                        vm.status.indexOf('BUILD') !== -1 ||
                        vm.status.indexOf('BOOT') !== -1
                    ) {
                        vmInfo.providerVisible = true;
                    } else {
                        vmInfo.providerVisible = false;
                    }

                    if (vm.metadata.host_name && vm.metadata.host_name.length >= 0) {
                        // remove trailing .
                        vmInfo.hostname =
                            vm.metadata.host_name.lastIndexOf('.') === vm.metadata.host_name.length - 1 ?
                                vm.metadata.host_name.slice(0, -1)
                                : vm.metadata.host_name;
                    } else {
                        vmInfo.hostname = '';
                    }
                    vmsWithAutoscaleTag[vm.id] = vmInfo;
                }
            });
            logger.silly('getTaggedInstances result: \n', vmsWithAutoscaleTag);
            deferred.resolve(vmsWithAutoscaleTag);
        }
    });
    return deferred.promise;
}

/**
 * Updates the metadata container for known autoscale group memebers
 *
 * @param {Object}    orchClient       - Openstack Heat client
 * @param {Object}    instances        - Instance dictionary to store
 * @param {String}    metadataUrl      - Autoscale metadata url for update
 *
 * @returns {Promise} Promise which will be resolved when the operation completes
 *                    or rejected if an error occurs.
 */
function updateRegisteredInstances(orchClient, instances, metadataUrl) {
    const deferred = q.defer();

    const headers = {
        'Content-Type': 'application/json'
    };

    logger.debug('Updating autoscale metadata.');

    const instancesData = {
        // data is the actual instances container, required by the openstack resource
        data: instances
    };
    instancesData.data.status = 'UPDATE';

    logger.silly('InstancesData:', instancesData);

    httpUtil.put(metadataUrl, { headers, body: instancesData })
        .then((response) => {
            logger.silly('Http PUT response: ', response);
            deferred.resolve(response);
        })
        .catch((error) => {
            logger.error('Unable to update autoscale metadata. Error response received: ', error);
            deferred.reject(error);
        });

    return deferred.promise;
}


/**
 * Removes an instance from the registry
 *
 * @param {Object}    orchClient             - Openstack Heat client
 * @param {String}    autoscaleMetadataUrl   - Autoscale metadata url for update
 * @param {String[]}  idsToDelete            - Ids of instances to be removed
 * @param {Object}    registeredInstances    - Current dictionary of known instances
 *
 * @returns {Promise} Promise which will be resolved when the operation completes
 *                    or rejected if an error occurs.
 */
function deregisterInstances(orchClient, autoscaleMetadataUrl, idsToDelete, registeredInstances) {
    const updatedInstances = registeredInstances;

    idsToDelete.forEach((id) => {
        if (updatedInstances[id]) {
            logger.silly('Removing instance from registry. Instance Id: ', id);
            // delete key from instances
            delete updatedInstances[id];
        }
    });

    return updateRegisteredInstances(orchClient, updatedInstances, autoscaleMetadataUrl);
}


/**
 * Gets the metadata associated with an instance
 *
 * @param {String}    instanceMetadataUrl   - Autoscale metadata url to use to retrieve instance data
 *
 * @returns {Promise} Promise which will be resolved when the operation completes with the instance data
 *                    or rejected if an error occurs.
 */
function getInstanceMetadata(instanceMetadataUrl) {
    return cloudUtil.getDataFromUrl(
        instanceMetadataUrl,
        {
            headers: {
                Metadata: true
            }
        }
    )
        .then((metaData) => {
            return JSON.parse(metaData);
        });
}


/**
 * Gets the url for the resource containing autoscale metadata
 *
 * @param {Object}    orchClient                  - Openstack Heat client
 * @param {String}    stackName                   - Name of the stack where the autoscale
 *                                                  metadata container is a resource of
 * @param {String}    autoscaleMetadataResource   - Name of the metadata container resource
 *
 * @returns {Promise} Promise which will be resolved with the URL when the operation completes
 *                    or rejected if an error occurs.
 */
function getAutoscaleMetadataStackResourceUrl(orchClient, stackName, autoscaleMetadataResource) {
    const deferred = q.defer();
    logger.debug('Retrieving autoscale metadata stack.resource url');

    orchClient.getResource(stackName, autoscaleMetadataResource, (err, resource) => {
        if (err) {
            logger.error('Error encountered while retrieving stack resource. Details: ', err);
            deferred.reject(err);
        } else {
            const resourceObj = resource;
            logger.silly('Metadata links and token:', resourceObj.links, orchClient._identity.token.id);

            const autoscaleResourceLinks = resourceObj.links;
            let autoscaleMetadataUrl;

            autoscaleResourceLinks.forEach((resourceLink) => {
                if (resourceLink.rel === 'self') {
                    autoscaleMetadataUrl = resourceLink.href;
                    logger.silly('Found href for autoscale resource:', autoscaleMetadataUrl);
                }
            });

            if (autoscaleMetadataUrl) {
                logger.debug(`Autoscale metadata resource URL: ${autoscaleMetadataUrl}`);
                deferred.resolve(autoscaleMetadataUrl);
            } else {
                // eslint-disable-next-line max-len
                const message = `ERROR: Unable to find metadata resource url for resource ${autoscaleMetadataResource} in stack ${stackName}`;
                logger.error(message);
                deferred.reject(message);
            }
        }
    });
    return deferred.promise;
}


/**
 * Gets the autoscale metadata by querying the stack resource endpoint
 *
 * @param {String}    url     - The full url to the stack resource
 * @param {String}    token   - Token used for authentication
 *
 * @returns {Promise} Promise which will be resolved with the autoscale data when the operation completes
 *                    or rejected if an error occurs.
 */
function getAutoscaleMetadataStackResource(url, token) {
    return cloudUtil.getDataFromUrl(
        url,
        {
            headers: {
                Metadata: true,
                'X-Auth-Token': token
            }
        }
    )
        .then((autoscaleResource) => {
            logger.silly('Autoscale resource: ', autoscaleResource);
            return autoscaleResource.resource;
        });
}

/**
* Gets the list of currently known instances that are part of the autoscale group
*
* @param {Object}    orchClient            - Openstack Heat client
* @param {String}    autoscaleMetadataUrl  - Name of the metadata resource
* @param {Boolean}   failOnNullOrEmpty     - Optionally toggle whether an error
*                                            should be thrown if no instances
*
* @returns {Promise} Promise which will be resolved with instances object when the operation completes
*                    or rejected if an error occurs.
*                    Each instance value should have the following properties, (at minimum):
*                   {
*                       isMaster: <Boolean>,
*                       hostname: <String>,
*                       mgmtIp: <String>,
*                       privateIp: <String>
*                       providerVisible: <Boolean> (does the cloud provider know about this instance)
*                   }
*/
function getRegisteredInstances(orchClient, autoscaleMetadataUrl, failOnNullOrEmpty) {
    const deferred = q.defer();

    let registeredInstances = {};
    let message;
    let autoscaleData;
    let instances;

    logger.debug('Getting current registered instances');

    const processFail = (typeof failOnNullOrEmpty !== 'undefined') ? failOnNullOrEmpty : true;

    getAutoscaleMetadataStackResource(autoscaleMetadataUrl, orchClient._identity.token.id)
        .then((autoscaleResource) => {
            if (!autoscaleResource) {
                message = 'ERROR: Unable to retrieve autoscale metadata resource';
                deferred.reject(new Error(message));
            } else {
                autoscaleData = autoscaleResource.attributes.data;
                if (!autoscaleData) {
                    if (processFail) {
                        message = 'ERROR: Data is null or empty. No registered instances found';
                        deferred.reject(new Error(message));
                    }
                } else {
                    instances = JSON.parse(autoscaleData.replace('1', 'instances')).instances;
                    if (typeof instances.status === 'undefined' || instances.status === 'INIT') {
                        if (processFail) {
                            message = 'ERROR: No registered instances found';
                            deferred.reject(new Error(message));
                        }
                    } else {
                        registeredInstances = instances;
                        // remove extraneous metadata status prop
                        delete registeredInstances.status;
                    }
                }
                logger.silly('getRegisteredInstances result: \n', registeredInstances);
                deferred.resolve(registeredInstances);
            }
        });

    return deferred.promise;
}

module.exports = OpenStackAutoscaleProvider;

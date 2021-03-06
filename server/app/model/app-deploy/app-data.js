/*
Copyright [2016] [Relevance Lab]

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/


var logger = require('_pr/logger')(module);
var mongoose = require('mongoose');
var ObjectId = require('mongoose').Types.ObjectId;
var uniqueValidator = require('mongoose-unique-validator');
var schemaValidator = require('_pr/model/utils/schema-validator');

// File which contains App Data DB schema and DAO methods. 

var Schema = mongoose.Schema;

var AppDataSchema = new Schema({
    projectId: String,
    envId: String,
    appName: String,
    version: String,
    upgrade: String,
    nexus:{
        repoURL: String,
        nodeIps: [String]
    },
    docker:[{
        image: String,
        container: String,
        port: String,
        nodeIp: String
    }]
});


// Save or update appData informations.
AppDataSchema.statics.createNewOrUpdate = function(appData, callback) {
    var that = this;
    this.find({
        projectId: appData.projectId,
        envId: appData.envId,
        appName: appData.appName,
        version: appData.version
    }, function(err, aData) {
        if (err) {
            logger.debug("Error fetching record.", err);
            callback(err, null);
        }
        if (aData.length) {
            var setData = {};
            var keys = Object.keys(appData);
            for (var i = 0; i < keys.length; i++) {
                setData[keys[i]] = appData[keys[i]];
            }
            that.update({
                projectId: appData.projectId,
                envId: appData.envId,
                appName: appData.appName,
                version: appData.version
            }, {
                $set: setData
            }, {
                upsert: false
            }, function(err, updatedData) {
                if (err) {
                    logger.debug("Failed to update: ", err);
                    callback(err, null);
                }
                callback(null, updatedData);
            });
        } else {
            var appDataObj = new that(appData);
            appDataObj.save(function(err, anAppData) {
                if (err) {
                    logger.debug("Got error while creating appData: ", err);
                    callback(err, null);
                }
                logger.debug("Creating appData: ", JSON.stringify(anAppData));
                callback(null, anAppData);
            });
        }
    });
};

// Get AppData by project,env,appName,version.
AppDataSchema.statics.getAppDataByProjectAndEnv = function(projectId, envId, appName, version, callback) {
    this.find({
        projectId: projectId,
        envId: envId,
        appName: appName,
        version: version
    }, function(err, anAppData) {
        if (err) {
            logger.debug("Got error while fetching appData: ", err);
            callback(err, null);
        }
        logger.debug("Got appData: ", JSON.stringify(anAppData));
        callback(null, anAppData);
    });
};

var AppData = mongoose.model("appData", AppDataSchema);
module.exports = AppData;
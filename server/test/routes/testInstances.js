/**
 * Created by Durgesh Sharma on 26/2/16.
 */

'use strict';
var assert = require('assert');
var supertest = require("supertest");
var should = require("should");
var xlsx = require('node-xlsx');
var util = require('util'),
    fs = require('fs');
var server = supertest.agent("http://localhost:3001");


before(function(done){
    server
        .post('/auth/signin')
        .send({username : 'superadmin', pass : 'superadmin@123'})
        .end(function(err,res){
            if (err) return done(err);
            done();
        });
})

/*describe("Check UnmanagedInstances List for Perticular Providers ",function(){

    it(" Unmanaged Instances List with Pagination ",function(done){
        server
            .get('/providers/56d41d26708c18ba15138941/unmanagedInstances?page=1&pageSize=5')
            .end(function(err,res){
                assert.equal(res.status, 200);
                assert.equal(res.body.length,5);
                done();
            });
    });

    it(" Search Unmanaged Instances List based on Status ",function(done){
        server
            .get('/providers/56d41d26708c18ba15138941/unmanagedInstances?status=running')
            .end(function(err,res){
                assert.equal(res.status, 200);
                assert.equal(res.body.length,10);
                assert.equal(res.body[0].state,'running');
                done();
            });
    });

    it(" Search Unmanaged Instances List based on OS Type with pagination",function(done){
        server
            .get('/providers/56d41d26708c18ba15138941/unmanagedInstances?page=1&pageSize=8&osType=linux')
            .end(function(err,res){
                assert.equal(res.status, 200);
                assert.equal(res.body.length,8);
                assert.equal(res.body[0].os,'linux');
                done();
            });
    });

});*/

describe("Check Import by IP  ",function(){

   /* it(" Import By IP with without Request Body ",function(done){
        server
            .post('/organizations/46d1da9a-d927-41dc-8e9e-7e926d927537/businessgroups/7e3500f1-58f9-43e2-b9eb-347b2e4d129d/projects/b38ccedc-da2c-4e2c-a278-c66333564719/environments/b40330fc-c03c-44a2-97ec-b966733641e6/addInstance')
            .end(function(err,res){
                assert.equal(res.status, 400);
                done();
            });
    });*/
    it(" Import By IP with with Request Body ",function(done){
        var obj = xlsx.parse(__dirname + '/data/dataSheets.xlsx');
        for(var i=0;i<(convertToJSON(obj[0].data)).length;i++) {
            var jsonData = convertToJSON(obj[0].data)[i];
            var reqBody = {
                "fqdn": jsonData.InstanceIP,
                "os": jsonData.InstanceType,
                "credentials": {
                    "username": jsonData.UserName,
                    "password": jsonData.Password
                },
                "configManagmentId": jsonData.ConfigManagID
            };
            var url = '/organizations/' + jsonData.OrgID + '/businessgroups/' + jsonData.BusGrpID + '/projects/' + jsonData.ProID + '/environments/' + jsonData.EnvID + '/addInstance';
            //console.log(reqBody);
            //console.log(url);
            server
                .post(url)
                .send(reqBody)
                .end(function (err, res) {
                    console.log(res.body);
                    assert.equal(res.body.orgId, jsonData.OrgID);
                    assert.equal(res.body.bgId, jsonData.BusGrpID);
                    assert.equal(res.body.projectId, jsonData.ProID);
                    assert.equal(res.body.envId, jsonData.EnvID);
                    assert.equal(res.body.instanceState, 'running');
                    assert.equal(res.status, 200);
                    done();

                });
        }

    });




});

function convertToJSON(array) {
    var first = array[0].join()
    var headers = first.split(',');

    var jsonData = [];
    for ( var i = 1, length = array.length; i < length; i++ )
    {

        var myRow = array[i].join();
        var row = myRow.split(',');

        var data = {};
        for ( var x = 0; x < row.length; x++ )
        {
            data[headers[x]] = row[x];
        }
        jsonData.push(data);

    }
    return jsonData;
};


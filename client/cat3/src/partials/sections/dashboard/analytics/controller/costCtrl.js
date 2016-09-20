(function (angular) {
    "use strict";
    angular.module('dashboard.analytics')
        .controller('costCtrl', ['$scope', '$rootScope', '$state','analyticsServices', 'genericServices', function ($scope,$rootScope,$state,analyticsServices,genSevs){
        $rootScope.stateItems = $state.params;
        // var treeNames = ['Analytics','Cost'];
        // $rootScope.$emit('treeNameUpdate', treeNames);
        $rootScope.organNewEnt=[];
        $rootScope.organNewEnt.org = '0';
            var costObj =this;
            costObj.pieChat={
                option:{
                    chart: {
                        type: 'pieChart',
                        margin: {
                            top: 20,
                            right: 0,
                            bottom: 60,
                            left:0
                        },
                        height:300,
                        x: function(d){return d.key;},
                        y: function(d){return d.y;},
                        showLabels: false,
                        showValues: true,
                        labelThreshold: 0.01,
                        labelSunbeamLayout: true,
                        legend: {

                        }
                    }
                },
                totalCoust:'',
                data:[]
            };

            costObj.barChat ={
                option: {
                    chart: {
                        type: 'multiBarChart',
                        height: 300,
                        margin: {
                            top: 20,
                            right: 20,
                            bottom: 60,
                            left: 40
                        },
                        duration: 50,
                        stacked: true,
                        x: function (d) {
                            return d.label;
                        },
                        y: function (d) {
                            return d.value;
                        },
                        showControls: false,
                        showValues: true,
                        xAxis: {
                            showMaxMin: false
                        },
                        yAxis: {
                            axisLabel: 'Values',
                            tickFormat: function (d) {
                                return d3.format(',.2f')(d);
                            }
                        },
                        zoom: {
                            enabled: true,
                            scaleExtent: [1, 10],
                            useFixedDomain: false,
                            useNiceScale: false,
                            horizontalOff: true,
                            verticalOff: true,
                            unzoomEventType: 'dblclick.zoom'
                        }

                    }
                },
                data:
                    [
                       {
                            "key": "EC2",
                            "values": []
                        },
                        {
                            "key": "RDS",
                            "values": []
                        },
                        {
                            "key": "S3",
                            "values": []
                        }
                    ]

            };

            costObj.costGridOptions = {
                columnDefs: [
                    { name:'name',field: 'name' },
                    { name:'totalCost',field: 'cost.totalCost'},
                    { name:'EC2',field:'cost.awsCosts.serviceCosts.ec2'},
                    { name:'RDS',field:'cost.awsCosts.serviceCosts.rds'},
                    { name:'S3',field:'cost.awsCosts.serviceCosts.s3'}
                ],
                enableGridMenu: true,
                enableSelectAll: true,
                exporterMenuPdf: false,
                exporterCsvFilename: 'costFile.csv',
                exporterCsvLinkElement: angular.element(document.querySelectorAll(".custom-csv-link-location")),
                onRegisterApi: function(gridApi){
                    $scope.gridApi = gridApi;
                }
            };

            var param={
                url:'src/partials/sections/dashboard/analytics/data/cost.json'
            };
            genSevs.promiseGet(param).then(function(result){
                costObj.costGridOptions.data = result.splitUpCosts.businessUnits;
                costObj.pieChat.totalCoust= result.cost.totalCost;
                angular.forEach(result.splitUpCosts.businessUnits,function (value) {
                    costObj.pieChat.data.push( {
                        key: value.name,
                        y:value.cost.totalCost
                    });
                    costObj.barChat.data[0].values.push( {
                        "label" :value.name ,
                        "value" : value.cost.awsCosts.serviceCosts.ec2
                    });
                    costObj.barChat.data[1].values.push( {
                        "label" :value.name ,
                        "value" : value.cost.awsCosts.serviceCosts.rds
                    });
                    costObj.barChat.data[2].values.push( {
                        "label" :value.name ,
                        "value" : value.cost.awsCosts.serviceCosts.s3
                    });
                });
                // angular.forEach(result.splitUpCosts.providers,function (valu) {
                //     costObj.pieChat.data.push( {
                //         key: valu.name,
                //         y:valu.cost.totalCost
                //     });
                // });
            });
        $scope.optionsLine= {
            chart: {
                type: 'stackedAreaChart',
                height: 250,
                margin : {
                    top: 20,
                    right: 20,
                    bottom: 30,
                    left: 40
                },
                x: function(d){return d[0];},
                y: function(d){return d[1];},
                useVoronoi: false,
                clipEdge: true,
                duration: 20,
                useInteractiveGuideline: true,
                xAxis: {
                    showMaxMin: false,
                    tickFormat: function(d) {
                        return d3.time.format('%x')(new Date(d))
                    }
                },
                yAxis: {
                    tickFormat: function(d){
                        return d3.format(',.2f')(d);
                    }
                },
                zoom: {
                    enabled: true,
                    scaleExtent: [1, 10],
                    useFixedDomain: false,
                    useNiceScale: false,
                    horizontalOff: true,
                    verticalOff: true,
                    unzoomEventType: 'dblclick.zoom'
                }
            }
        };

        $scope.dataLine = [  {
            key: "EC2",
            values: [ [ 1083297600000 , 30] , [ 1085976000000 , 50] , [ 1088568000000 , 20] ]

        },
            {
                key: "RDS",
                values: [ [ 1083297600000 , 20] , [ 1085976000000 ,20] , [ 1088568000000 , 60]]

            },


            {
                key: "S3",
                values: [ [ 1083297600000 , 10] , [ 1085976000000 , 50],[ 1088568000000 , 40]]
            }];

    }]);
})(angular);

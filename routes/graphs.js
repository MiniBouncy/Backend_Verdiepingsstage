var express = require('express');
var q = require('q');
var promise = require('promise');
var router = express.Router();
var querystring = require('querystring');
var https = require('https');
var http = require('http');
var request = require('request');
var hostCount = [];
hostNames = [],
hostid = [],
hisId = [];

router.route('/totalIncidents')

.get(function(req, res, next) {  

  var accessKey = '71c038febdad47d21ce268d5c43e05c9081f59e0d2c6efd3745ed08b13bff88d';
  var secretKey = '9e88e79329678436bcf54281031f1236ca8d74ecb8166bbc4ff7f3937a8c9bfa';

  // var postData = querystring.stringify({
  //   'history_id': 1322
  // });

  var xApi  = "accessKey=" + accessKey + "; secretKey=" +secretKey;
  var options = {
    rejectUnauthorized: false, 
    hostname: 'monitor.insitesecurity.nl',
    path: '/scans/1020',
    port: 443,
    method: 'GET',
    headers: {
      'Content-Type': 'application/json',
      'X-ApiKeys': xApi
    }
  };


  var graphReq = https.request(options, (graphRes) => {
//    console.log('STATUS: ' + graphRes.statusCode);
    // console.log('HEADERS: ' + JSON.stringify(graphRes.headers));
    if((graphRes.statusCode==200) || (graphRes.statusCode == 201)) {
      
    } else {
      res.status(500);
      res.send({
        success: false,
        message: 'Something went wrong at the connection'
      });
    }
    graphRes.setEncoding('utf8');
   // var date = new Date();
    var response = '';
    var dates = [];
    var critical = [];
    var high = [];
    var medium = [];
    var low = [];
    var informational = [];
    var amount = [];
    var plugins = [];


    graphRes.on('data', (chunk) => {
//    console.log('BODY: ' + JSON.stringify(chunk));
      response += chunk;
    });
    //message: Object.keys('hosts')

    graphRes.on('end', () => {
      var json = JSON.parse(response);

      var a;
      var b;
      var c;
      var d;
      var e;
      var f;
      var g;
      var startTime = [];
      var endTime = [];

      for(a = 0 ; a < json.dashboard.vulnerabilities.history.length ; a++) {
        dates.push(json.dashboard.vulnerabilities.history[a].report_date);
      }

      for(b = 0 ; b <json.dashboard.vulnerabilities.history.length ; b++) {
        critical.push(json.dashboard.vulnerabilities.history[b].critical);
        high.push(json.dashboard.vulnerabilities.history[b].high);
        medium.push(json.dashboard.vulnerabilities.history[b].med);
        low.push(json.dashboard.vulnerabilities.history[b].low);
        informational.push(json.dashboard.vulnerabilities.history[b].info);
      }

    //  console.log('count: '+json.dashboard.vulnerabilities[0]);
    
      for(c = 0 ; c <json.dashboard.vulnerabilities.top.length ; c++) {
        amount.push(json.dashboard.vulnerabilities.top[c].count);
        plugins.push(json.dashboard.vulnerabilities.top[c].plugin_name);
      }

      for(d = 0 ; d <json.history.length ; d++){
        hisId.push(json.history[d].history_id);
      }
  //    console.log('hostnames: '+hostNames);

      for(e = 0 ; e <json.hosts.length ; e++){
        hostCount.push(json.hosts[e].hostname);
      }

       for(g = 0 ; g <hostCount.length ; g++){
          for(f = 0 ; f <hostNames.length ; f++){
            if(hostNames[f] === hostCount[g]){
        //      console.log(json.hosts[g].hostname);
              hostid.push(json.hosts[g].host_id);
            }
          }          
        }

   //   console.log('incidenten: ' +incidents);
      res.send({
        succes: true,
        message: json.dashboard.vulnerabilities.history,
        dates: dates,
        critical: critical,
        high: high,
        med: medium,
        low: low,
        inf: informational,
        amount: amount,
        plugins: plugins,
      });
    })
  });
  // write data to request body
  graphReq.write(xApi);
  graphReq.end();
})

router.route('/incidentHistory')

.get(function(req, res, next) {  

  var accessKey2 = '71c038febdad47d21ce268d5c43e05c9081f59e0d2c6efd3745ed08b13bff88d';
  var secretKey2 = '9e88e79329678436bcf54281031f1236ca8d74ecb8166bbc4ff7f3937a8c9bfa';

  var xApi2  = "accessKey=" + accessKey2 + "; secretKey=" +secretKey2;
  var options = {
    rejectUnauthorized: false, 
    hostname: 'monitor.insitesecurity.nl',
    path: '/plugins/plugin/85886',
    port: 443,
    method: 'GET',
    headers: {
      'Content-Type': 'application/json',
      'X-ApiKeys': xApi2
    }
  };


  var incReq = https.request(options, (incRes) => {
//    console.log('STATUS: ' + graphRes.statusCode);
    // console.log('HEADERS: ' + JSON.stringify(graphRes.headers));
    if((incRes.statusCode==200) || (incRes.statusCode == 201)) {
      
    } else {
      res.status(500);
      res.send({
        success: false,
        message: 'Something went wrong at the connection'
      });
    }
    incRes.setEncoding('utf8');
    var response2 = '';
    var att_name = [];
    var att_value = [];


    incRes.on('data', (chunk) => {
//    console.log('BODY: ' + JSON.stringify(chunk));
      response2 += chunk;
    });

    incRes.on('end', () => {
      var json = JSON.parse(response2);
      var l;

      for(l = 0 ; l < json.attributes.length ; l++) {
        if(json.attributes[l].attribute_name == 'vuln_publication_date') {
          att_name.push(json.attributes[l].attribute_name);
          att_value.push(json.attributes[l].attribute_value);
        } else if (json.attributes[l].attribute_name == 'plugin_publication_date') {
          att_name.push(json.attributes[l].attribute_name);
          att_value.push(json.attributes[l].attribute_value);
        } else if(json.attributes[l].attribute_name == 'patch_publication_date') {
          att_name.push(json.attributes[l].attribute_name);
          att_value.push(json.attributes[l].attribute_value);
        } else if(json.attributes[l].attribute_name == 'plugin_modification_date') {
          att_name.push(json.attributes[l].attribute_name);
          att_value.push(json.attributes[l].attribute_value);
        }
      }
      // console.log('att_name: ' +att_name);
      // console.log('att_value: ' +att_value);

   //   console.log('incidenten: ' +incidents);
      res.send({
        succes: true,
        att_name: att_name,
        att_value: att_value
      });
    })
  });
  // write data to request body
  incReq.write(xApi2);
  incReq.end();
})

router.route('/hostHistory')

.get(function(req, res, next) {  

  var accessKey3 = '71c038febdad47d21ce268d5c43e05c9081f59e0d2c6efd3745ed08b13bff88d';
  var secretKey3 = '9e88e79329678436bcf54281031f1236ca8d74ecb8166bbc4ff7f3937a8c9bfa';

  var xApi3  = "accessKey=" + accessKey3 + "; secretKey=" +secretKey3;
  var options = {
    rejectUnauthorized: false, 
    hostname: 'monitor.insitesecurity.nl',
    path: '/scans/1020/plugins/88906',
    port: 443,
    method: 'GET',
    headers: {
      'Content-Type': 'application/json',
      'X-ApiKeys': xApi3
    }
  };


  var hostReq = https.request(options, (hostRes) => {
//    console.log('STATUS: ' + graphRes.statusCode);
    // console.log('HEADERS: ' + JSON.stringify(graphRes.headers));
    if((hostRes.statusCode==200) || (hostRes.statusCode == 201)) {
      
    } else {
      res.status(500);
      res.send({
        success: false,
        message: 'Something went wrong at the connection'
      });
    }
    hostRes.setEncoding('utf8');
    var response3 = '';
    var outputs = [];

    var d;
    var m;
    var n;


    hostRes.on('data', (chunk) => {
//    console.log('BODY: ' + JSON.stringify(chunk));
      response3 += chunk;
    });


    hostRes.on('end', () => {
      var json = JSON.parse(response3);

      for(m = 0 ; m < json.outputs.length ; m++) {
       // outputs.push(json.outputs[m].ports);\
       outputs.push(json.outputs[m].ports['0 / tcp / ']);
  //     console.log(json.outputs[m].ports['0 / tcp / ']);
      }

      for(n = 0 ; n < outputs[0].length ; n++) {
       // console.log(outputs[0][n].hostname);
       hostNames.push(outputs[0][n].hostname);
      }

   //   console.log('incidenten: ' +incidents);
      res.send({
        succes: true,
        hosts: hostNames,
        plugin: json.info.plugindescription.pluginattributes.plugin_information.plugin_id,
              
      });
    })
  });
  // write data to request body
  hostReq.write(xApi3);
  hostReq.end();
})

router.route('/scanHosts')

.get(function(req, res, next) { 

  var getVulnerabilities = function (options) {
      var deferred = q.defer();
      http.request({url: options}, function(error, res, body) {
      if(!error && res.statusCode == 200) {
     //   console.log(body);
        deferred.resolve(body);
      } else{
          deferred.reject(new Error(error));
        }
      })
      return deferred.promise;
    }
    

  var accessKey4 = '71c038febdad47d21ce268d5c43e05c9081f59e0d2c6efd3745ed08b13bff88d';
  var secretKey4 = '9e88e79329678436bcf54281031f1236ca8d74ecb8166bbc4ff7f3937a8c9bfa';

  var y;
  var z;
  var histReq;

  var xApi4  = "accessKey=" + accessKey4 + "; secretKey=" +secretKey4;
 
  for(y = 0 ; y <hostid.length ; y++) {
    for(z = 0 ; z <hisId.length ; z++){
       var options = {
        rejectUnauthorized: false, 
        hostname: 'http://monitor.insitesecurity.nl/scans/1020/hosts/'+hostid[y]+'?history_id='+hisId[z],
        port: 443,
        method: 'GET',
        headers: {
          'Content-Type': 'application/json',
          'X-ApiKeys': xApi4
        }
      };
 //     console.log(options);

  //    var stringed = JSON.stringify(options);
 //     console.log('stringed: '+stringed);

      getVulnerabilities(options)
      .then(function(options) {
        console.log('stringed');
        res.send(200);
      })
      .catch(function(error) {
    //  console.log('err', error);
        res.json({error: error.message});
      })
    }
  } 
  
})
module.exports = router;

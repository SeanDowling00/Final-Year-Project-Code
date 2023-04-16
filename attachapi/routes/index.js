var express = require('express');
var router = express.Router();
var request = require('request');
var fs = require('fs');
var multer = require('multer');
var upload = multer({ dest: 'uploads/' });

/* GET home page. */
router.get('/', function (req, res, next) {
  res.render('index', { title: 'Express' });
});

router.post('/upload', upload.single('file'), function (req, res, next) {
  var file = req.file;
  var formData = {
    file: {
      value: fs.createReadStream(file.path),
      options: {
        filename: file.name
      }
    },
    apikey: '813861dc28625873a20aa3dddcd0b33471ab4bc15063a8268a422d199b75506c'
  };
  request.post({
    url: 'https://www.virustotal.com/vtapi/v2/file/scan',
    formData: formData
  }, function (err, httpResponse, body) {
    if (err) {
      console.error('Error:', err);
      return res.status(500).send(err);
    }
    console.log('Upload successful! Server responded with:', body);

    // Request the report for the file from VirusTotal using the resource URL returned in the response
    var response = JSON.parse(body);
    var resourceUrl = response.resource;
    var reportUrl = 'https://www.virustotal.com/vtapi/v2/file/report';
    var params = {
      apikey: '813861dc28625873a20aa3dddcd0b33471ab4bc15063a8268a422d199b75506c',
      resource: resourceUrl
    };
    request.get({
      url: reportUrl,
      qs: params
    }, function (err, httpResponse, body) {
      if (err) {
        console.error('Error:', err);
        return res.status(500).send(err);
      }
      console.log('Report retrieved! Server responded with:', body);

      // Parse the report data and extract the required information
      var reportData = JSON.parse(body);
      var permalink = reportData.permalink;
      var positives = reportData.positives;
      var total = reportData.total;
      var sha256 = reportData.sha256;

      // Render an HTML page with the extracted information
      res.render('result', {
        title: 'Scan Result',
        permalink: permalink,
        positives: positives,
        total: total,
        sha256: sha256,
      });
    });
  });
});


module.exports = router;

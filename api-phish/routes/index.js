var express = require("express");
var router = express.Router();
var axios = require("axios");

/* GET home page. */
router.get("/scan", function (req, res, next) {
  const url = req.query.url;

  // Define URLs for each API call
  const urlscanUrl = `https://urlscan.io/api/v1/search/?q=domain:${url}`;
  const ipqualityscoreUrl = `https://ipqualityscore.com/api/json/url/LfHU7WVWlnCXHZoafHXyHQvo62m2sGS1/${url}`;
  const virustotalUrl = `https://www.virustotal.com/vtapi/v2/url/report?apikey=813861dc28625873a20aa3dddcd0b33471ab4bc15063a8268a422d199b75506c&resource=${url}&allinfo=false&scan=0)`;

  Promise.all([
    axios.get(urlscanUrl),
    axios.get(ipqualityscoreUrl),
    axios.get(virustotalUrl),
  ])
    .then(function (responses) {
      const urlscanResult = responses[0].data;
      const ipqualityscoreResult = responses[1].data;
      const virustotalResult = responses[2].data;

      const virustotalPositives = virustotalResult.positives;
      const virustotalTotal = virustotalResult.total;
      const virustotalpermalink = virustotalResult.permalink;

      const urlscanDomain = urlscanResult.results[0].page.domain;
      const urlscanScreenshotLink = urlscanResult.results[0].screenshot;
      const urlscanIP = urlscanResult.results[0].page.ip;

      const ipqsUnsafe = ipqualityscoreResult.unsafe;
      const ipqsURL = ipqualityscoreResult.ip_address;
      const ipqsRisk = ipqualityscoreResult.risk_score;

      const virustotalRisk = virustotalResult.positives;

      let riskLevel = "";
      let riskClass = "";

      if (ipqsRisk > 10 && virustotalRisk > 10) {
        riskLevel = "Malicious";
        riskClass = "danger";
      } else if (
        ipqsRisk < 10 &&
        ipqsRisk > 5 &&
        virustotalRisk < 10 &&
        virustotalRisk > 5
      ) {
        riskLevel = "Moderately Risky";
        riskClass = "caution";
      } else {
        riskLevel = "Safe";
        riskClass = "success";
      }

      console.log(urlscanResult);
      console.log(ipqualityscoreResult);
      console.log(virustotalResult);

      res.render("index", {
        title: "API Results",
        urlscanData: JSON.stringify(urlscanResult),
        urlscanDomain: urlscanDomain,
        urlscanScreenshotLink: urlscanScreenshotLink,
        urlscanIP: urlscanIP,
        urlscanURL: urlscanUrl,

        ipqualityscoreData: JSON.stringify(ipqualityscoreResult),
        ipqualityscoreUnsafe: ipqsUnsafe,
        ipqualityscoreURL: ipqsURL,
        ipqualityscoreRisk: ipqsRisk,
        ipqualityscoreURL: ipqualityscoreUrl,

        virustotalData: JSON.stringify(virustotalResult),
        virustotalPositives: virustotalPositives,
        virustotalTotal: virustotalTotal,
        virustotalpermalink: virustotalpermalink,
        virustotalURL: virustotalUrl,

        riskLevel: riskLevel,
        riskClass: riskClass,
      });
    })
    .catch(function (error) {
      console.error(error);
      res.render("index", { title: "Error", error: error.message });
    });
});

module.exports = router;

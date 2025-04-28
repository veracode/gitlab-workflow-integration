const { execSync } = require('child_process');
const path = require('path');
const { attacheResult, exitOnFailure, updateErrorMessage} = require('../../utility/utils');
const scaScanIssue = require('../../veracode-issues/scaScanIssue');
const displayScanResult = require('../../displayScanResult');

async function scaScan(clone_url, scaAgenToken, scaUrl, sourceBranch, breakBuildOnFinding, breakBuildOnError, userErrorMessage, createIssue) {
  try {
    const command = `curl -sSL https://download.sourceclear.com/ci.sh | sh -s -- scan --url ${clone_url} --ref ${sourceBranch} --recursive --allow-dirty`;
    const output = execSync(command, { encoding: 'utf-8', env: { ...process.env, SRCCLR_API_TOKEN: scaAgenToken, SRCCLR_API_URL: scaUrl } });
    const jsonCommand = `curl -sSL https://download.sourceclear.com/ci.sh | sh -s -- scan --url ${clone_url} --ref ${sourceBranch} --json=scaScan.json --recursive --allow-dirty`;
    const jsonOutput = execSync(jsonCommand, { encoding: 'utf-8', env: { ...process.env, SRCCLR_API_TOKEN: scaAgenToken, SRCCLR_API_URL: scaUrl } });
    if (output.includes("Full Report Details")) {
      const veracodeArtifactsDir = path.join(__dirname, '../../veracode-artifacts');
      attacheResult(veracodeArtifactsDir, 'scaScan.json', jsonOutput);
    }
    const parsedOutput = JSON.parse(jsonOutput); 
    if (parsedOutput.records[0].vulnerabilities.length) {
      await displayScanResult(parsedOutput.records);
      if(createIssue){
        await scaScanIssue(parsedOutput);
      }
      console.log(`Veracode SCA scan executed successfully.`);
      console.log(output);
      exitOnFailure(breakBuildOnFinding);
    }else{
      await displayScanResult([]);
      console.log(`Veracode SCA scan executed successfully.`);
      console.log(output);
    }
  } catch (error) {
    error = updateErrorMessage(breakBuildOnError, userErrorMessage, error.message);
    console.error(`Error occurred during SCA scan: ${error}`);
    exitOnFailure(breakBuildOnError);
  }
}

module.exports = scaScan;
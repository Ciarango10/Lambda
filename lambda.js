const jsforce = require('jsforce');
const jwt = require('jsonwebtoken');

exports.handler = async (event) => {

  // Get private key from environment variables
  const privateKey = process.env.SF_PRIVATE_KEY.trim();

  // Extract credentials from request
  const { username, consumerKey, packageId } = JSON.parse(event.body);
  if (!username || !consumerKey || !packageId) {
    return {
      statusCode: 400,
      body: JSON.stringify({ error: 'Missing required fields' })
    };
  }
  
  try {
    const token = jwt.sign({
      iss: consumerKey, 
      sub: username,     
      aud: 'https://login.salesforce.com',
      exp: Math.floor(Date.now() / 1000) + 300 // 5 min
    }, privateKey, { algorithm: 'RS256' });

    // Authenticate using JWT Bearer Flow
    const authResponse = await fetch('https://login.salesforce.com/services/oauth2/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
        assertion: token
      })
    });

    // Handle auth errors
    if (!authResponse.ok) {
      const errorData = await authResponse.json();
      throw new Error(errorData.error_description || 'JWT authentication failed');
    }

    const authData = await authResponse.json();

    // Initialize JSForce connection
    const conn = new jsforce.Connection({
      instanceUrl: authData.instance_url,
      accessToken: authData.access_token
    });

    // Install specified package
    const result = await conn.tooling.sobject('PackageInstallRequest').create({
      SubscriberPackageVersionKey: packageId,
      NameConflictResolution: 'Block',
      SecurityType: 'None' // Admin Only
    });

    return {
      statusCode: 200,
      body: JSON.stringify({
        success: true,
        requestId: result.id,
        message: "Package update initiated - may take several minutes",
        statusCheckEndpoint: `/status?id=${result.id}`
      })
    };

  } catch (err) {
    // Enhanced error handling with specific solutions
    console.error("Error:", err);
    
    let errorMessage = "Authentication error";
    if (err.message.includes('unsupported_grant_type')) {
      errorMessage = "JWT Bearer Flow not enabled in Salesforce Connected App";
    } else if (err.message.includes('invalid client credentials')) {
      errorMessage = "Invalid Salesforce credentials";
    }

    return {
      statusCode: 500,
      body: JSON.stringify({ 
        error: errorMessage,
        solution: "Contact your Salesforce administrator"
      })
    };
  }
};
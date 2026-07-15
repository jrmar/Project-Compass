// Project Compass — Entra External ID (CIAM) authentication
const COMPASS_AUTH = {
  clientId:   '282ae3c8-0539-4146-b1e8-4db8812a987a',
  tenantName: 'projectcompassio',          // CIAM subdomain (from Run user flow URL)
  tenantId:   'bf607dab-b1ad-4ef6-95f8-0560666c716b', // directory tenant ID
  scopes:     ['openid', 'profile', 'email'],
};

function buildMsalConfig() {
  const base = window.location.origin;
  return {
    auth: {
      clientId:                  COMPASS_AUTH.clientId,
      authority:                 `https://${COMPASS_AUTH.tenantName}.ciamlogin.com/${COMPASS_AUTH.tenantId}/`,
      knownAuthorities:          [`${COMPASS_AUTH.tenantName}.ciamlogin.com`],
      redirectUri:               `${base}/app/auth-callback.html`,
      postLogoutRedirectUri:     `${base}/app/login.html`,
      navigateToLoginRequestUrl: false,
    },
    cache: {
      cacheLocation:          'sessionStorage',
      storeAuthStateInCookie:  false,
    },
    system: {
      allowNativeBroker: false,
    },
  };
}

async function initMsal() {
  const pca = new msal.PublicClientApplication(buildMsalConfig());
  await pca.initialize();
  return pca;
}

export const Authorization = () => {
  return `https://www.facebook.com/${process.env.FACEBOOK_API_VERSION}/dialog/oauth?client_id=${process.env.FACEBOOK_LOGIN_CLIENT_ID}&redirect_uri=${process.env.FACEBOOK_LOGIN_REDIRECT_URI}&response_type=code&scope=email,public_profile`;
};

export const Redirect = (code) => {
  return {
    message: "Redirect received. Handle the code and exchange it for an access token.",
    code,
  };
};

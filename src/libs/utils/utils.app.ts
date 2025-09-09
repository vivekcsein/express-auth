/**
 * Returns cookie expiration time in milliseconds for given number of days.
 */
export const getCookieExpiryInDays = (days: number): number => {
  return days * 24 * 60 * 60 * 1000; //express cookie plugin expect it in miliseconds
};

/**
 * Returns cookie expiration time in milliseconds for given number of minutes.
 */
export const getCookieExpiryInMinutes = (minutes: number): number => {
  return minutes * 60 * 1000; // seconds
};

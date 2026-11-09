# BIRB app

Where I've heard birds with Merlin Sound ID, from my eBird export. Live at https://birb-app.netlify.app

- `index.html`: the whole app (map, Habitat world, Collection, accounts).
- `netlify/functions/api.mjs`: accounts and stored eBird uploads (Netlify Functions + Netlify Blobs).
  Passcodes are salted and hashed with scrypt; sessions are signed tokens; uploads have home addresses tidied to the nearest town.

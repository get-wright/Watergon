# Patched NodeGoat image for Watergon.
#
# Upstream Dockerfile (github.com/OWASP/NodeGoat) does `npm install --production`
# which strips devDependencies. The `db:seed` script needs `cross-env` and
# `grunt`, both devDeps, so the seed step crashes with "sh: cross-env: not found"
# and the pod CrashLoopBackOffs.
#
# Fix: install all dependencies (NODE_ENV=test, no --production flag).
# Also adds netcat-openbsd so the deploy manifest's `until nc -z` wait loop works.
FROM node:lts-alpine
ENV NODE_ENV=test
RUN apk add --no-cache git python3 make g++ netcat-openbsd
WORKDIR /home/node/app
COPY package*.json ./
RUN npm install
COPY . .
EXPOSE 4000
CMD ["npm", "start"]

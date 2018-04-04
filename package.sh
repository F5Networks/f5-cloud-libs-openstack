#!/bin/bash
if [[ $1 == '--no-deps' ]]; then
    rm -rf node_modules
    npm install --production
fi

# We have an old version of npm on the build machines which installs peer dependencies.
# We do not want this/
rm -rf node_modules/@f5devcentral

tar -C .. --exclude=".git*" --exclude="test" --exclude="${PWD##*/}/dist" --exclude="doc" --exclude="${PWD##*/}/.vscode" -zcf dist/f5-cloud-libs-openstack.tar.gz f5-cloud-libs-openstack

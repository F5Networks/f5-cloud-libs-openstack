#!/bin/bash
if [[ $1 == '--no-deps' ]]; then
    rm -rf node_modules
    npm install --production
fi

tar -C .. --exclude=".git*" --exclude="test" --exclude="${PWD##*/}/dist" --exclude="doc" --exclude="${PWD##*/}/.vscode" -zcvf dist/f5-cloud-libs-openstack.tar.gz f5-cloud-libs-openstack

#!/bin/bash

here=$(dirname "$0")
test -n "$here" -a -d "$here" || (echo "Cannot determine build dir. FIXME!" && exit 1)

. "$here"/../../base.sh # functions we use below (fail, et al)

if [ ! -d 'contrib' ]; then
    fail "Please run this script from the top-level git directory"
fi

pushd .

docker_version=`docker --version`

if [ "$?" != 0 ]; then
    echo ''
    echo "Please install docker by issuing the following commands (assuming you are on Ubuntu):"
    echo ''
    echo '$ curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo apt-key add -'
    echo '$ sudo add-apt-repository "deb [arch=amd64] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable"'
    echo '$ sudo apt-get update'
    echo '$ sudo apt-get install -y docker-ce'
    echo ''
    fail "Docker is required to build for Windows"
fi

set -e

info "Using docker: $docker_version"

IMGNAME="electrumabc-srcdist-builder-img"
MAPPED_DIR=/opt/electrumabc
CONTAINERNAME="electrumabc-srcdist-builder-cont"

info "Creating docker image ..."
docker build -t $IMGNAME \
    contrib/build-linux/srcdist_docker \
    || fail "Failed to create docker image"

mkdir "${ELECTRUM_ROOT}/contrib/build-linux/home" || fail "Failed to create home directory"

(
    docker run $DOCKER_RUN_TTY \
    -e HOME="$MAPPED_DIR/contrib/build-linux/home" \
    -e BUILD_DEBUG="$BUILD_DEBUG" \
    --name $CONTAINERNAME \
    -v ${ELECTRUM_ROOT}:$MAPPED_DIR:delegated \
    --rm \
    --workdir $MAPPED_DIR/contrib/build-linux/srcdist_docker \
    -u $(id -u $USER):$(id -g $USER) \
    $IMGNAME \
    ./_build.sh
) || fail "Build inside docker container failed"

popd

info "Removing temporary docker HOME ..."
rm -fr "${ELECTRUM_ROOT}/contrib/build-linux/home"

echo ""
info "Done. Built SrdDist archives (.tar.gz, .zip) have been placed in dist/"

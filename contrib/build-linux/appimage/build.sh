#!/bin/bash

here=$(dirname "$0")
test -n "$here" -a -d "$here" || (echo "Cannot determine build dir. FIXME!" && exit 1)

. "$here"/../../base.sh # functions we use below (fail, et al)

if [ ! -d 'contrib' ]; then
    fail "Please run this script form the top-level git directory"
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

# Only set SUDO if its not been set already
if [ -z ${SUDO+x} ] ; then
    SUDO=""  # on macOS (and others?) we don't do sudo for the docker commands ...
    if [ $(uname) = "Linux" ]; then
        # .. on Linux we do
        SUDO="sudo"
    fi
fi

DOCKER_SUFFIX=ub1804
IMGNAME="electrumabc-appimage-builder-img-$DOCKER_SUFFIX"
CONTAINERNAME="electrumabc-appimage-builder-cont-$DOCKER_SUFFIX"

info "Creating docker image ..."
$SUDO docker build -t $IMGNAME \
    -f contrib/build-linux/appimage/Dockerfile_$DOCKER_SUFFIX \
    --build-arg UBUNTU_MIRROR=$UBUNTU_MIRROR \
    contrib/build-linux/appimage \
    || fail "Failed to create docker image"

MAPPED_DIR=/opt/electrumabc

mkdir "${ELECTRUM_ROOT}/contrib/build-linux/appimage/home" || fail "Failed to create home directory"

(
    $SUDO docker run $DOCKER_RUN_TTY \
    -e HOME="$MAPPED_DIR/contrib/build-linux/appimage/home" \
    -e BUILD_DEBUG="$BUILD_DEBUG" \
    --name $CONTAINERNAME \
    -v ${ELECTRUM_ROOT}:$MAPPED_DIR:delegated \
    --rm \
    --workdir $MAPPED_DIR/contrib/build-linux/appimage \
    -u $(id -u $USER):$(id -g $USER) \
    $IMGNAME \
    ./_build.sh
) || fail "Build inside docker container failed"

popd

info "Removing temporary docker HOME ..."
rm -fr "${ELECTRUM_ROOT}/contrib/build-linux/appimage/home"

echo ""
info "Done. Built AppImage has been placed in dist/"

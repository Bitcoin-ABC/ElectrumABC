#!/bin/bash

here=$(dirname "$0")
test -n "$here" -a -d "$here" || (echo "Cannot determine build dir. FIXME!" && exit 1)

GIT_SUBMODULE_SKIP=1
. "$here"/../../base.sh # functions we use below (fail, et al)
unset GIT_SUBMODULE_SKIP

if [ ! -z "$1" ]; then
    REV="$1"
else
    fail "Please specify a release tag or branch to build (eg: master or 4.0.0, etc)"
fi

if [ ! -d 'contrib' ]; then
    fail "Please run this script form the top-level git directory"
fi

pushd .

docker_version=`docker --version`

if [ "$?" != 0 ]; then
    fail "Docker is required to build"
fi

set -e

info "Using docker: $docker_version"

# Only set SUDO if its not been set already
if [ -z ${SUDO+x} ] ; then
    SUDO="sudo"
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

# This is the place where we checkout and put the exact revision we want to work
# on. Docker will run mapping this directory to /opt/electrumabc
FRESH_CLONE=`pwd`/contrib/build-linux/fresh_clone
FRESH_CLONE_DIR=$FRESH_CLONE/$GIT_DIR_NAME
MAPPED_DIR=/opt/electrumabc

(
    $SUDO rm -fr $FRESH_CLONE && \
        mkdir -p $FRESH_CLONE && \
        cd $FRESH_CLONE  && \
        git clone $GIT_REPO && \
        cd $GIT_DIR_NAME && \
        git checkout $REV
) || fail "Could not create a fresh clone from git"

mkdir "$FRESH_CLONE_DIR/contrib/build-linux/home" || fail "Failed to create home directory"

(
    # NOTE: We propagate forward the GIT_REPO override to the container's env,
    # just in case it needs to see it.
    $SUDO docker run $DOCKER_RUN_TTY \
    -e HOME="$MAPPED_DIR/contrib/build-linux/home" \
    -e GIT_REPO="$GIT_REPO" \
    -e BUILD_DEBUG="$BUILD_DEBUG" \
    --name $CONTAINERNAME \
    -v $FRESH_CLONE_DIR:$MAPPED_DIR:delegated \
    --rm \
    --workdir $MAPPED_DIR/contrib/build-linux/appimage \
    -u $(id -u $USER):$(id -g $USER) \
    $IMGNAME \
    ./_build.sh $REV
) || fail "Build inside docker container failed"

popd

info "Copying built files out of working clone..."
mkdir -p dist/
cp -fpvR $FRESH_CLONE_DIR/dist/* dist/ || fail "Could not copy files"

info "Removing $FRESH_CLONE ..."
$SUDO rm -fr $FRESH_CLONE

echo ""
info "Done. Built AppImage has been placed in dist/"

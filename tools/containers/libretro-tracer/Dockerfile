FROM gcc@sha256:435c3cbc2ad1c25fbc1684c367808ff0ca2035a1bed56734a40165ab5cd7e3bd

# Keep the Debian archive signed while pinning the package index to the source
# snapshot present in the reviewed GCC image.
RUN set -eux; \
    sed -i \
      -e 's#^URIs: http://deb.debian.org/debian$#URIs: https://snapshot.debian.org/archive/debian/20261020T213255Z/#' \
      -e 's#^URIs: http://deb.debian.org/debian-security$#URIs: https://snapshot.debian.org/archive/debian-security/20261020T213255Z/#' \
      /etc/apt/sources.list.d/debian.sources; \
    apt-get update -o Acquire::Check-Valid-Until=false; \
    apt-get install --yes --no-install-recommends cmake=3.31.6-2; \
    rm -rf /var/lib/apt/lists/*; \
    python3 --version; \
    git --version; \
    make --version; \
    gcc --version; \
    test "$(cmake --version | sed -n '1s/^cmake version //p')" = 3.31.6

#!/usr/bin/env bash

rm -f "dist/*"

package=`grep module go.mod | cut -d " " -f 2`
package_split=(${package//\// })
package_name=${package_split[-1]}

platforms=("windows/amd64" "windows/386" "windows/arm64" "linux/amd64" "linux/386" "linux/arm64" "darwin/amd64" "darwin/arm64")

for platform in "${platforms[@]}"
do
    platform_split=(${platform//\// })
    GOOS=${platform_split[0]}
    GOARCH=${platform_split[1]}
    output_name=$package_name
    archive_name=$package_name'-'$GOOS'-'$GOARCH
    if [ $GOOS = "windows" ]; then
        output_name+='.exe'
	archive_name+='.zip'
    else
        archive_name+='.tar.gz'
    fi

    echo "CGO_ENABLED=0 GOOS=$GOOS GOARCH=$GOARCH go build -o ""dist/$output_name"" $package"
    CGO_ENABLED=0 GOOS=$GOOS GOARCH=$GOARCH go build -o "dist/$output_name" $package
    if [ $? -ne 0 ]; then
        echo 'An error has occurred! Aborting the script execution...'
        exit 1
    fi
    echo "go run github.com/mholt/archiver/v3/cmd/arc@latest -folder-safe=false -overwrite archive ""dist/$archive_name"" ""dist/$output_name"" README.md LICENSE"
    go run github.com/mholt/archiver/v3/cmd/arc@latest -folder-safe=false -overwrite archive "dist/$archive_name" "dist/$output_name" README.md LICENSE
    rm "dist/$output_name"

    echo ""
done

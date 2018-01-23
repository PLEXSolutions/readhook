#!/bin/bash
REPOSITORY=polyverse/readhook
ASSET_NAME=readhook.so
RELEASE_TAG=v1.0.0

# Delete the current assets and release (if exists)
asset_id_from_release_tag_and_name=$(pv github asset-id-from-release-tag-and-name $REPOSITORY $RELEASE_TAG $ASSET_NAME)
echo "asset-id-from-release-tag-and-name:\n$asset_id_from_release_tag_and_name\n"

delete_release_asset=$(pv github delete-release-asset $REPOSITORY $asset_id_from_release_tag_and_name)
echo "delete-release-asset:\n$delete_release_asset\n"

delete_release_by_tag=$(pv github delete-release-by-tag $REPOSITORY $RELEASE_TAG)
echo "delete-release-by-tag:\n$delete_release_by_tag\n"

# (Re-)create the release and upload the library binary file asset
create_release=$(pv github create-release $REPOSITORY $RELEASE_TAG)
echo "create-release:\n$create_release\n"

upload_release_file_by_tag=$(pv github upload-release-file-by-tag $REPOSITORY $RELEASE_TAG $ASSET_NAME)
echo "upload-release-file-by-tag:\n$upload_release_file_by_tag\n"

#!/bin/bash
declare -r      repository=polyverse/readhook
declare -r -a   assets=(basehook.so fullhook.so noophook.so nullhook.so)
declare         tag=$1

# If no tag is given, use the jenkins release assets
if [[ "$tag" == "" ]]; then tag=jenkins3d; fi

process_asset()
{
	# Delete the current asset (if it exists)
	asset_id_from_release_tag_and_name=$(pv github asset-id-from-release-tag-and-name $repository $tag $1)
	printf "asset-id-from-release-tag-and-name:\n$asset_id_from_release_tag_and_name\n"

	delete_release_asset=$(pv github delete-release-asset $repository $asset_id_from_release_tag_and_name)
	printf "delete-release-asset:\n$delete_release_asset\n"

	upload_release_file_by_tag=$(pv github upload-release-file-by-tag $repository $tag dll/$1)
	printf "upload-release-file-by-tag:\n$upload_release_file_by_tag\n"
}

# Process each asset in the list
for asset in ${assets[*]}; do process_asset $asset; done

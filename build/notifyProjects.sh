# if nothing changed, we're done
NUM_FILES_CHANGED=$(git diff HEAD^ --name-only | wc -l)
if [[ $NUM_FILES_CHANGED == 0 ]]; then
    echo No files changed
    exit 0
fi

pushd "$(dirname "$0")"

RELEASE=^release-.*
HOTFIX=^hf-.*

if [[ "$CI_BUILD_REF_NAME" =~ $RELEASE ]]; then
    SPECIAL_BRANCH=$RELEASE
elif [[ "$CI_BUILD_REF_NAME" =~ $HOTFIX ]]; then
    SPECIAL_BRANCH=$HOTFIX
fi

CLOUD_LIBS_BRANCHES=$(node parseBranches.js "$(curl -s --insecure -H "PRIVATE-TOKEN: $API_TOKEN" ${CI_BASE_URL}/${CLOUD_LIBS_PROJECT_ID}/repository/branches)")
CLOUD_IAPPS_BRANCHES=$(node parseBranches.js "$(curl -s --insecure -H "PRIVATE-TOKEN: $API_TOKEN" ${CI_BASE_URL}/${CLOUD_IAPPS_PROJECT_ID}/repository/branches)")

if [[ -n $SPECIAL_BRANCH ]]; then
    # if we are on a release or hotfix branch, look for a release or hotfix branch in f5-cloud-libs
    for BRANCH in $CLOUD_LIBS_BRANCHES; do
        if [[ "$BRANCH" =~ $SPECIAL_BRANCH ]]; then
            CLOUD_LIBS_BRANCH_TO_TRIGGER="$BRANCH"
            break
        fi
    done

    for BRANCH in $CLOUD_IAPPS_BRANCHES; do
        if [[ "$BRANCH" =~ $SPECIAL_BRANCH ]]; then
            CLOUD_IAPPS_BRANCH_TO_TRIGGER="$BRANCH"
            break
        fi
    done
else
    # otherwise, look for a branch with a name that matches our branch
    for BRANCH in $CLOUD_LIBS_BRANCHES; do
        if [[ "$BRANCH" == "$CI_BUILD_REF_NAME" ]]; then
            CLOUD_LIBS_BRANCH_TO_TRIGGER="$BRANCH"
            break
        fi
    done

    for BRANCH in $CLOUD_IAPPS_BRANCHES; do
        if [[ "$BRANCH" == "$CI_BUILD_REF_NAME" ]]; then
            CLOUD_IAPPS_BRANCH_TO_TRIGGER="$BRANCH"
            break
        fi
    done
fi

if [[ -n "$CLOUD_LIBS_BRANCH_TO_TRIGGER" ]]; then
    echo Triggering build of f5-cloud-libs "$CLOUD_LIBS_BRANCH_TO_TRIGGER" branch
    curl -s --insecure -X POST -F "token=$CLOUD_LIBS_TRIGGER_TOKEN" -F "ref=$CLOUD_LIBS_BRANCH_TO_TRIGGER" -F "variables[UPDATE_HASH_PROJECT_ID]=$CI_PROJECT_ID" -F "variables[UPDATE_HASH_BUILD_ID]=${CI_BUILD_ID}" -F "variables[UPDATE_HASH_REPO]=$CI_PROJECT_NAME" -F "variables[UPDATE_HASH_BRANCH]=$CI_BUILD_REF_NAME" -F "variables[UPDATE_HASH_FILE]=dist/${CI_PROJECT_NAME}.tar.gz" ${CI_BASE_URL}/${CLOUD_LIBS_PROJECT_ID}/trigger/builds
    echo
else
    echo No f5-cloud-libs branch to trigger
fi

if [[ -n "$CLOUD_IAPPS_BRANCH_TO_TRIGGER" ]]; then
    echo Triggering build of f5-cloud-iapps "$CLOUD_IAPPS_BRANCH_TO_TRIGGER" branch
    curl -s --insecure -X POST -F "token=$CLOUD_IAPPS_TRIGGER_TOKEN" -F "ref=$CLOUD_IAPPS_BRANCH_TO_TRIGGER" -F "variables[UPDATE_HASH_PROJECT_ID]=$CI_PROJECT_ID" -F "variables[UPDATE_HASH_BUILD_ID]=${CI_BUILD_ID}" -F "variables[UPDATE_HASH_REPO]=$CI_PROJECT_NAME" -F "variables[UPDATE_HASH_BRANCH]=$CI_BUILD_REF_NAME" -F "variables[UPDATE_HASH_FILE]=dist/${CI_PROJECT_NAME}.tar.gz" ${CI_BASE_URL}/${CLOUD_IAPPS_PROJECT_ID}/trigger/builds
    echo
else
    echo No f5-cloud-iapps branch to trigger
fi

popd

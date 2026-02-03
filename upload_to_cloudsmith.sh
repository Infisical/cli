#!/bin/bash
set -eo pipefail

cd dist || { echo "Failed to cd into dist"; exit 1; }

# Validate signing key ID is configured
if [ -z "$INFISICAL_CLI_REPO_SIGNING_KEY_ID" ]; then
    echo "Error: INFISICAL_CLI_REPO_SIGNING_KEY_ID not set"
    exit 1
fi

# Validate required environment variables for S3 uploads
validate_s3_env() {
    local missing=()
    [ -z "$INFISICAL_CLI_S3_BUCKET" ] && missing+=("INFISICAL_CLI_S3_BUCKET")
    [ -z "$AWS_ACCESS_KEY_ID" ] && missing+=("AWS_ACCESS_KEY_ID")
    [ -z "$AWS_SECRET_ACCESS_KEY" ] && missing+=("AWS_SECRET_ACCESS_KEY")
    
    if [ ${#missing[@]} -gt 0 ]; then
        echo "Warning: Missing environment variables for S3 uploads: ${missing[*]}"
        echo "S3 upload steps will be skipped."
        return 1
    fi
    return 0
}

S3_ENABLED=false
validate_s3_env && S3_ENABLED=true

# ============================================
# APK - Upload to Cloudsmith (keep until S3 is validated)
# ============================================
for i in *.apk; do
    [ -f "$i" ] || break
    cloudsmith push alpine --republish infisical/infisical-cli/alpine/any-version $i
done

# ============================================
# APK - Upload to S3 and generate APKINDEX
# ============================================
if ls *.apk 1> /dev/null 2>&1 && [ "$S3_ENABLED" = "true" ]; then
    echo "Processing APK packages..."
    
    # Create local directory structure
    mkdir -p apk-staging/stable/main/x86_64
    mkdir -p apk-staging/stable/main/aarch64
    
    # Sort APK files by architecture
    for i in *.apk; do
        [ -f "$i" ] || break
        if [[ "$i" == *"aarch64"* ]] || [[ "$i" == *"arm64"* ]]; then
            echo "Copying $i to aarch64/"
            cp "$i" apk-staging/stable/main/aarch64/
        elif [[ "$i" == *"x86_64"* ]] || [[ "$i" == *"amd64"* ]]; then
            echo "Copying $i to x86_64/"
            cp "$i" apk-staging/stable/main/x86_64/
        else
            echo "Warning: Unknown architecture for $i, skipping S3 upload"
        fi
    done
    
    # Sync existing packages from S3 (to preserve old versions)
    echo "Syncing existing APK packages from S3..."
    aws s3 sync "s3://$INFISICAL_CLI_S3_BUCKET/apk/" apk-staging/ --exclude "*/APKINDEX.tar.gz"
    
    # Validate APK private key exists
    if [ ! -f "$APK_PRIVATE_KEY_PATH" ]; then
        echo "Error: APK private key not found at $APK_PRIVATE_KEY_PATH"
        exit 1
    fi
    
    # Generate APKINDEX using Alpine container
    echo "Generating APKINDEX.tar.gz using Alpine container..."
    docker run --rm \
        -v "$(pwd)/apk-staging:/repo" \
        -v "$APK_PRIVATE_KEY_PATH:/keys/infisical.rsa:ro" \
        alpine:3.21 sh -c '
            set -e
            echo "Installing alpine-sdk..."
            apk add --no-cache alpine-sdk || { echo "Failed to install alpine-sdk"; exit 1; }
            
            # Process x86_64
            if ls /repo/stable/main/x86_64/*.apk 1> /dev/null 2>&1; then
                echo "Generating APKINDEX for x86_64..."
                cd /repo/stable/main/x86_64
                apk index -o APKINDEX.tar.gz *.apk
                abuild-sign -k /keys/infisical.rsa APKINDEX.tar.gz
                echo "x86_64 APKINDEX signed successfully"
            fi
            
            # Process aarch64
            if ls /repo/stable/main/aarch64/*.apk 1> /dev/null 2>&1; then
                echo "Generating APKINDEX for aarch64..."
                cd /repo/stable/main/aarch64
                apk index -o APKINDEX.tar.gz *.apk
                abuild-sign -k /keys/infisical.rsa APKINDEX.tar.gz
                echo "aarch64 APKINDEX signed successfully"
            fi
        '
    
    # Upload everything to S3
    echo "Uploading APK repository to S3..."
    aws s3 sync apk-staging/ "s3://$INFISICAL_CLI_S3_BUCKET/apk/"
    
    echo "APK packages uploaded successfully"
fi

for i in *.deb; do
    [ -f "$i" ] || break
    deb-s3 upload --bucket=$INFISICAL_CLI_S3_BUCKET --prefix=deb --visibility=private --sign=$INFISICAL_CLI_REPO_SIGNING_KEY_ID --preserve-versions $i
done


# ============================================
# RPM - Upload to Cloudsmith (keep until S3 is validated)
# ============================================
for i in *.rpm; do
    [ -f "$i" ] || break
    cloudsmith push rpm --republish infisical/infisical-cli/any-distro/any-version $i
done

# ============================================
# RPM - Upload to S3 and regenerate repo metadata
# ============================================
if [ "$S3_ENABLED" = "true" ]; then
    for i in *.rpm; do
        [ -f "$i" ] || break
        
        # Sign the RPM package
        rpmsign --addsign --key-id="$INFISICAL_CLI_REPO_SIGNING_KEY_ID" "$i"
        
        # Upload to S3
        aws s3 cp "$i" "s3://$INFISICAL_CLI_S3_BUCKET/rpm/Packages/"
    done

    # Regenerate RPM repository metadata with mkrepo
    # Note: mkrepo uses boto3 which automatically reads AWS_ACCESS_KEY_ID and
    # AWS_SECRET_ACCESS_KEY from environment variables set in the workflow
    if ls *.rpm 1> /dev/null 2>&1; then
        export GPG_SIGN_KEY=$INFISICAL_CLI_REPO_SIGNING_KEY_ID
        mkrepo "s3://$INFISICAL_CLI_S3_BUCKET/rpm" \
            --s3-region="us-east-1" \
            --sign
    fi
fi

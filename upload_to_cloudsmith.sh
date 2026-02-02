cd dist

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
if ls *.apk 1> /dev/null 2>&1; then
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
        else
            echo "Copying $i to x86_64/"
            cp "$i" apk-staging/stable/main/x86_64/
        fi
    done
    
    # Sync existing packages from S3 (to preserve old versions)
    echo "Syncing existing APK packages from S3..."
    aws s3 sync "s3://$INFISICAL_CLI_S3_BUCKET/apk/" apk-staging/ --exclude "*/APKINDEX.tar.gz"
    
    # Generate APKINDEX using Alpine container
    echo "Generating APKINDEX.tar.gz using Alpine container..."
    docker run --rm \
        -v "$(pwd)/apk-staging:/repo" \
        -v "$APK_PRIVATE_KEY_PATH:/keys/infisical.rsa:ro" \
        alpine:3.21 sh -c '
            set -e
            apk add --no-cache alpine-sdk > /dev/null 2>&1
            
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
for i in *.rpm; do
    [ -f "$i" ] || break
    
    # Sign the RPM package
    rpmsign --addsign --key-id="$INFISICAL_CLI_REPO_SIGNING_KEY_ID" "$i"
    
    # Upload to S3
    aws s3 cp "$i" "s3://$INFISICAL_CLI_S3_BUCKET/rpm/Packages/"
done

# Regenerate RPM repository metadata with mkrepo
if ls *.rpm 1> /dev/null 2>&1; then
    export GPG_SIGN_KEY=$INFISICAL_CLI_REPO_SIGNING_KEY_ID
    mkrepo s3://$INFISICAL_CLI_S3_BUCKET/rpm \
        --s3-access-key-id="$AWS_ACCESS_KEY_ID" \
        --s3-secret-access-key="$AWS_SECRET_ACCESS_KEY" \
        --s3-region="us-east-1" \
        --sign
fi

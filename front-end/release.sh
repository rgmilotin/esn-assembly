#!/bin/bash

# project specific parameters
AWS_PROFILE='esn-assembly-hu'
DOMAIN_PROD='assembly.esn.hu'
DOMAIN_DEV='dev.assembly.esn.hu'

# other parameters
ACTION=$1
SRC_FOLDER="src/"
C='\033[4;32m' # color
NC='\033[0m'   # reset (no color)

# disable pagination in aws cli commands
export AWS_PAGER=""

# set the script to exit in case of errors
set -o errexit

# Resolve the AWS CLI in native shells and in Git Bash/WSL on Windows.
AWS_CLI='aws'
if ! command -v "${AWS_CLI}" >/dev/null 2>&1
then
  for candidate in \
    'aws.exe' \
    '/c/Program Files/Amazon/AWSCLIV2/aws.exe' \
    '/mnt/c/Program Files/Amazon/AWSCLIV2/aws.exe' \
    '/mnt/c/Users/'"${USERNAME}"'/AppData/Local/Programs/Amazon/AWSCLIV2/aws.exe'
  do
    if command -v "${candidate}" >/dev/null 2>&1 || [ -x "${candidate}" ]
    then
      AWS_CLI="${candidate}"
      break
    fi
  done
fi
if ! command -v "${AWS_CLI}" >/dev/null 2>&1 && [ ! -x "${AWS_CLI}" ]
then
  echo "AWS CLI not found. Install it and ensure it is available on PATH." >&2
  exit 1
fi

# parameters validation
if [ "${ACTION}" != "dev" ] && [ "${ACTION}" != "prod" ]
then
  echo -e "${C}Target environment: dev|prod${NC}"
  echo -e "${C}\t - dev:    release the front-end in the development environment${NC}"
  echo -e "${C}\t - prod:   release the front-end in the production environment${NC}"
  exit -1
fi

if [ "${ACTION}" == 'prod' ]
then
  DOMAIN=${DOMAIN_PROD}
else
  DOMAIN=${DOMAIN_DEV}
fi
echo -e "${C}Target domain: ${DOMAIN}${NC}"

# install the npm modules
echo -e "${C}Installing npm modules...${NC}"
npm i --silent 1>/dev/null

# lint the code in search for errors
echo -e "${C}Linting...${NC}"
npm run lint ${SRC_FOLDER} 1>/dev/null

# compile the project's typescript code
echo -e "${C}Compiling...${NC}"
npx ng build --configuration production 1>/dev/null

# get the target CloudFront distribution and S3 bucket (from the domain)
DISTRIBUTION=`"${AWS_CLI}" cloudfront list-distributions --query "DistributionList.Items[?contains(Aliases.Items, '${DOMAIN}')].Id | [0]" --profile ${AWS_PROFILE} --output text | tr -d '\r'`
if [ -z "${DISTRIBUTION}" ] || [ "${DISTRIBUTION}" == "None" ]
then
  echo "No CloudFront distribution found for ${DOMAIN}." >&2
  exit 1
fi
BUCKET=`"${AWS_CLI}" cloudfront get-distribution --id ${DISTRIBUTION} --profile ${AWS_PROFILE} --output text \
 --query "Distribution.DistributionConfig.Origins.Items[0].DomainName" | tr -d '\r' | cut -d "." -f 1`
if [ -z "${BUCKET}" ] || [ "${BUCKET}" == "None" ]
then
  echo "No S3 bucket found for CloudFront distribution ${DISTRIBUTION}." >&2
  exit 1
fi

# upload the project's files to the S3 bucket
echo -e "${C}Uploading...${NC}"
"${AWS_CLI}" s3 sync ./www s3://${BUCKET} --profile ${AWS_PROFILE} --delete --exclude ".well-known/*" 1>/dev/null

# invalidate old common files from the CloudFront distribution
echo -e "${C}Cleaning...${NC}"
MSYS_NO_PATHCONV=1 "${AWS_CLI}" cloudfront create-invalidation --profile ${AWS_PROFILE} --distribution-id ${DISTRIBUTION} \
  --paths "/index.html" "/assets/i18n*" \
  1>/dev/null

echo -e "${C}Done!${NC}"
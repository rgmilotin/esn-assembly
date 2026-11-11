/**
 * The codename of the project.
 */
export const PROJECT = 'esn-assembly-hu';
/**
 * The purchased domain to use.
 */
export const DOMAIN = 'assembly.esn.hu';
/**
 * An additional custom domain to use.
 */
export const PROD_CUSTOM_DOMAIN: string | null = 'assembly.esn.hu';
/**
 * Use `external` when DNS records are managed outside AWS, or `route53` to
 * let AWS manage hosted-zone records and certificate validation.
 */
export const DNS_MODE: DnsMode = 'external';

export const SES_SOURCE_ADDRESS = {
  external: 'noreply@assembly.esn.hu',
  route53: `no-reply@${DOMAIN.split('.').slice(-2).join('.')}`
}[DNS_MODE];

export const parameters: Parameters = {
  project: PROJECT,
  apiDomain: 'api.'.concat(DOMAIN),
  webSocketApiDomain: 'socket.'.concat(DOMAIN),
  mediaDomain: 'media.'.concat(DOMAIN),
  apiCertificateARN: 'arn:aws:acm:eu-central-1:167975317134:certificate/341cdb01-d699-4fa1-8065-e747e071f96a',
  webSocketCertificateARN: 'arn:aws:acm:eu-central-1:167975317134:certificate/15738515-e2e3-48d6-9bc1-58316059ad1e',
  frontEndCertificateARN: 'arn:aws:acm:us-east-1:167975317134:certificate/ced7b4f9-38d0-4c6d-b36f-15bea0906824',
  mediaCertificateARN: 'arn:aws:acm:us-east-1:167975317134:certificate/ced7b4f9-38d0-4c6d-b36f-15bea0906824',
  sesIdentityARN: 'arn:aws:ses:eu-central-1:167975317134:identity/noreply@assembly.esn.hu',
  sesNotificationTopicARN:
    'arn:aws:sns:eu-central-1:167975317134:esn-assembly-hu-ses-DomainIdentitySesNotificationTopic44F98B89-2VwjalQIQWVy',
  dnsMode: DNS_MODE
};

export const stages: { [stage: string]: Stage } = {
  prod: {
    domain: DOMAIN,
    alternativeDomains: PROD_CUSTOM_DOMAIN ? [PROD_CUSTOM_DOMAIN] : undefined,
    destroyDataOnDelete: false,
    logLevel: 'INFO'
  },
  dev: {
    domain: 'dev.'.concat(DOMAIN),
    destroyDataOnDelete: true,
    logLevel: 'DEBUG'
  }
};

export interface Parameters {
  /**
   * Project key (unique to the AWS account).
   */
  project: string;
  /**
   * HTTP API for each environment will be available at `${apiDomain}/${env.stage}`.
   */
  apiDomain: string;
  /**
   * Web Socket API for each environment will be available at `${apiDomain}/${env.stage}`.
   */
  webSocketApiDomain: string;
  /**
   * The domain name where to reach the front-end's media files.
   */
  mediaDomain: string;
  /**
   * The custom front-end certificate ARN to use, to support alternative domains.
   */
  frontEndCertificateARN?: string;
  apiCertificateARN?: string;
  webSocketCertificateARN?: string;
  mediaCertificateARN?: string;
  sesIdentityARN?: string;
  sesNotificationTopicARN?: string;
  dnsMode: DnsMode;
}

export type DnsMode = 'route53' | 'external';

export interface Stage {
  /**
   * The domain name where to reach the front-end.
   */
  domain: string;
  /**
   * The (optional) alternative domain names to reach the front-end.
   */
  alternativeDomains?: string[];
  /**
   * Whether to delete the data when the environment is deleted.
   * It should be True for dev and False for prod environments.
   */
  destroyDataOnDelete: boolean;
  /**
   * The minimum level of log to print in functions (default: `INFO`).
   */
  logLevel?: 'TRACE' | 'DEBUG' | 'INFO' | 'WARN' | 'ERROR' | 'FATAL';
}

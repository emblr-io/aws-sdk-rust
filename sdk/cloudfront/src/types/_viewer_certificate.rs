// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>A complex type that determines the distribution's SSL/TLS configuration for communicating with viewers.</p>
/// <p>If the distribution doesn't use <code>Aliases</code> (also known as alternate domain names or CNAMEs)—that is, if the distribution uses the CloudFront domain name such as <code>d111111abcdef8.cloudfront.net</code>—set <code>CloudFrontDefaultCertificate</code> to <code>true</code> and leave all other fields empty.</p>
/// <p>If the distribution uses <code>Aliases</code> (alternate domain names or CNAMEs), use the fields in this type to specify the following settings:</p>
/// <ul>
/// <li>
/// <p>Which viewers the distribution accepts HTTPS connections from: only viewers that support <a href="https://en.wikipedia.org/wiki/Server_Name_Indication">server name indication (SNI)</a> (recommended), or all viewers including those that don't support SNI.</p>
/// <ul>
/// <li>
/// <p>To accept HTTPS connections from only viewers that support SNI, set <code>SSLSupportMethod</code> to <code>sni-only</code>. This is recommended. Most browsers and clients support SNI.</p></li>
/// <li>
/// <p>To accept HTTPS connections from all viewers, including those that don't support SNI, set <code>SSLSupportMethod</code> to <code>vip</code>. This is not recommended, and results in additional monthly charges from CloudFront.</p></li>
/// </ul></li>
/// <li>
/// <p>The minimum SSL/TLS protocol version that the distribution can use to communicate with viewers. To specify a minimum version, choose a value for <code>MinimumProtocolVersion</code>. For more information, see <a href="https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/distribution-web-values-specify.html#DownloadDistValues-security-policy">Security Policy</a> in the <i>Amazon CloudFront Developer Guide</i>.</p></li>
/// <li>
/// <p>The location of the SSL/TLS certificate, <a href="https://docs.aws.amazon.com/acm/latest/userguide/acm-overview.html">Certificate Manager (ACM)</a> (recommended) or <a href="https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_server-certs.html">Identity and Access Management (IAM)</a>. You specify the location by setting a value in one of the following fields (not both):</p>
/// <ul>
/// <li>
/// <p><code>ACMCertificateArn</code></p></li>
/// <li>
/// <p><code>IAMCertificateId</code></p></li>
/// </ul></li>
/// </ul>
/// <p>All distributions support HTTPS connections from viewers. To require viewers to use HTTPS only, or to redirect them from HTTP to HTTPS, use <code>ViewerProtocolPolicy</code> in the <code>CacheBehavior</code> or <code>DefaultCacheBehavior</code>. To specify how CloudFront should use SSL/TLS to communicate with your custom origin, use <code>CustomOriginConfig</code>.</p>
/// <p>For more information, see <a href="https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/using-https.html">Using HTTPS with CloudFront</a> and <a href="https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/using-https-alternate-domain-names.html"> Using Alternate Domain Names and HTTPS</a> in the <i>Amazon CloudFront Developer Guide</i>.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ViewerCertificate {
    /// <p>If the distribution uses the CloudFront domain name such as <code>d111111abcdef8.cloudfront.net</code>, set this field to <code>true</code>.</p>
    /// <p>If the distribution uses <code>Aliases</code> (alternate domain names or CNAMEs), set this field to <code>false</code> and specify values for the following fields:</p>
    /// <ul>
    /// <li>
    /// <p><code>ACMCertificateArn</code> or <code>IAMCertificateId</code> (specify a value for one, not both)</p></li>
    /// <li>
    /// <p><code>MinimumProtocolVersion</code></p></li>
    /// <li>
    /// <p><code>SSLSupportMethod</code></p></li>
    /// </ul>
    pub cloud_front_default_certificate: ::std::option::Option<bool>,
    /// <p>If the distribution uses <code>Aliases</code> (alternate domain names or CNAMEs) and the SSL/TLS certificate is stored in <a href="https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_server-certs.html">Identity and Access Management (IAM)</a>, provide the ID of the IAM certificate.</p>
    /// <p>If you specify an IAM certificate ID, you must also specify values for <code>MinimumProtocolVersion</code> and <code>SSLSupportMethod</code>.</p>
    pub iam_certificate_id: ::std::option::Option<::std::string::String>,
    /// <p>If the distribution uses <code>Aliases</code> (alternate domain names or CNAMEs) and the SSL/TLS certificate is stored in <a href="https://docs.aws.amazon.com/acm/latest/userguide/acm-overview.html">Certificate Manager (ACM)</a>, provide the Amazon Resource Name (ARN) of the ACM certificate. CloudFront only supports ACM certificates in the US East (N. Virginia) Region (<code>us-east-1</code>).</p>
    /// <p>If you specify an ACM certificate ARN, you must also specify values for <code>MinimumProtocolVersion</code> and <code>SSLSupportMethod</code>.</p>
    pub acm_certificate_arn: ::std::option::Option<::std::string::String>,
    /// <p>If the distribution uses <code>Aliases</code> (alternate domain names or CNAMEs), specify which viewers the distribution accepts HTTPS connections from.</p>
    /// <ul>
    /// <li>
    /// <p><code>sni-only</code> – The distribution accepts HTTPS connections from only viewers that support <a href="https://en.wikipedia.org/wiki/Server_Name_Indication">server name indication (SNI)</a>. This is recommended. Most browsers and clients support SNI.</p></li>
    /// <li>
    /// <p><code>vip</code> – The distribution accepts HTTPS connections from all viewers including those that don't support SNI. This is not recommended, and results in additional monthly charges from CloudFront.</p></li>
    /// <li>
    /// <p><code>static-ip</code> - Do not specify this value unless your distribution has been enabled for this feature by the CloudFront team. If you have a use case that requires static IP addresses for a distribution, contact CloudFront through the <a href="https://console.aws.amazon.com/support/home">Amazon Web ServicesSupport Center</a>.</p></li>
    /// </ul>
    /// <p>If the distribution uses the CloudFront domain name such as <code>d111111abcdef8.cloudfront.net</code>, don't set a value for this field.</p>
    pub ssl_support_method: ::std::option::Option<crate::types::SslSupportMethod>,
    /// <p>If the distribution uses <code>Aliases</code> (alternate domain names or CNAMEs), specify the security policy that you want CloudFront to use for HTTPS connections with viewers. The security policy determines two settings:</p>
    /// <ul>
    /// <li>
    /// <p>The minimum SSL/TLS protocol that CloudFront can use to communicate with viewers.</p></li>
    /// <li>
    /// <p>The ciphers that CloudFront can use to encrypt the content that it returns to viewers.</p></li>
    /// </ul>
    /// <p>For more information, see <a href="https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/distribution-web-values-specify.html#DownloadDistValues-security-policy">Security Policy</a> and <a href="https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/secure-connections-supported-viewer-protocols-ciphers.html#secure-connections-supported-ciphers">Supported Protocols and Ciphers Between Viewers and CloudFront</a> in the <i>Amazon CloudFront Developer Guide</i>.</p><note>
    /// <p>On the CloudFront console, this setting is called <b>Security Policy</b>.</p>
    /// </note>
    /// <p>When you're using SNI only (you set <code>SSLSupportMethod</code> to <code>sni-only</code>), you must specify <code>TLSv1</code> or higher.</p>
    /// <p>If the distribution uses the CloudFront domain name such as <code>d111111abcdef8.cloudfront.net</code> (you set <code>CloudFrontDefaultCertificate</code> to <code>true</code>), CloudFront automatically sets the security policy to <code>TLSv1</code> regardless of the value that you set here.</p>
    pub minimum_protocol_version: ::std::option::Option<crate::types::MinimumProtocolVersion>,
    /// <p>This field is deprecated. Use one of the following fields instead:</p>
    /// <ul>
    /// <li>
    /// <p><code>ACMCertificateArn</code></p></li>
    /// <li>
    /// <p><code>IAMCertificateId</code></p></li>
    /// <li>
    /// <p><code>CloudFrontDefaultCertificate</code></p></li>
    /// </ul>
    #[deprecated]
    pub certificate: ::std::option::Option<::std::string::String>,
    /// <p>This field is deprecated. Use one of the following fields instead:</p>
    /// <ul>
    /// <li>
    /// <p><code>ACMCertificateArn</code></p></li>
    /// <li>
    /// <p><code>IAMCertificateId</code></p></li>
    /// <li>
    /// <p><code>CloudFrontDefaultCertificate</code></p></li>
    /// </ul>
    #[deprecated]
    pub certificate_source: ::std::option::Option<crate::types::CertificateSource>,
}
impl ViewerCertificate {
    /// <p>If the distribution uses the CloudFront domain name such as <code>d111111abcdef8.cloudfront.net</code>, set this field to <code>true</code>.</p>
    /// <p>If the distribution uses <code>Aliases</code> (alternate domain names or CNAMEs), set this field to <code>false</code> and specify values for the following fields:</p>
    /// <ul>
    /// <li>
    /// <p><code>ACMCertificateArn</code> or <code>IAMCertificateId</code> (specify a value for one, not both)</p></li>
    /// <li>
    /// <p><code>MinimumProtocolVersion</code></p></li>
    /// <li>
    /// <p><code>SSLSupportMethod</code></p></li>
    /// </ul>
    pub fn cloud_front_default_certificate(&self) -> ::std::option::Option<bool> {
        self.cloud_front_default_certificate
    }
    /// <p>If the distribution uses <code>Aliases</code> (alternate domain names or CNAMEs) and the SSL/TLS certificate is stored in <a href="https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_server-certs.html">Identity and Access Management (IAM)</a>, provide the ID of the IAM certificate.</p>
    /// <p>If you specify an IAM certificate ID, you must also specify values for <code>MinimumProtocolVersion</code> and <code>SSLSupportMethod</code>.</p>
    pub fn iam_certificate_id(&self) -> ::std::option::Option<&str> {
        self.iam_certificate_id.as_deref()
    }
    /// <p>If the distribution uses <code>Aliases</code> (alternate domain names or CNAMEs) and the SSL/TLS certificate is stored in <a href="https://docs.aws.amazon.com/acm/latest/userguide/acm-overview.html">Certificate Manager (ACM)</a>, provide the Amazon Resource Name (ARN) of the ACM certificate. CloudFront only supports ACM certificates in the US East (N. Virginia) Region (<code>us-east-1</code>).</p>
    /// <p>If you specify an ACM certificate ARN, you must also specify values for <code>MinimumProtocolVersion</code> and <code>SSLSupportMethod</code>.</p>
    pub fn acm_certificate_arn(&self) -> ::std::option::Option<&str> {
        self.acm_certificate_arn.as_deref()
    }
    /// <p>If the distribution uses <code>Aliases</code> (alternate domain names or CNAMEs), specify which viewers the distribution accepts HTTPS connections from.</p>
    /// <ul>
    /// <li>
    /// <p><code>sni-only</code> – The distribution accepts HTTPS connections from only viewers that support <a href="https://en.wikipedia.org/wiki/Server_Name_Indication">server name indication (SNI)</a>. This is recommended. Most browsers and clients support SNI.</p></li>
    /// <li>
    /// <p><code>vip</code> – The distribution accepts HTTPS connections from all viewers including those that don't support SNI. This is not recommended, and results in additional monthly charges from CloudFront.</p></li>
    /// <li>
    /// <p><code>static-ip</code> - Do not specify this value unless your distribution has been enabled for this feature by the CloudFront team. If you have a use case that requires static IP addresses for a distribution, contact CloudFront through the <a href="https://console.aws.amazon.com/support/home">Amazon Web ServicesSupport Center</a>.</p></li>
    /// </ul>
    /// <p>If the distribution uses the CloudFront domain name such as <code>d111111abcdef8.cloudfront.net</code>, don't set a value for this field.</p>
    pub fn ssl_support_method(&self) -> ::std::option::Option<&crate::types::SslSupportMethod> {
        self.ssl_support_method.as_ref()
    }
    /// <p>If the distribution uses <code>Aliases</code> (alternate domain names or CNAMEs), specify the security policy that you want CloudFront to use for HTTPS connections with viewers. The security policy determines two settings:</p>
    /// <ul>
    /// <li>
    /// <p>The minimum SSL/TLS protocol that CloudFront can use to communicate with viewers.</p></li>
    /// <li>
    /// <p>The ciphers that CloudFront can use to encrypt the content that it returns to viewers.</p></li>
    /// </ul>
    /// <p>For more information, see <a href="https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/distribution-web-values-specify.html#DownloadDistValues-security-policy">Security Policy</a> and <a href="https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/secure-connections-supported-viewer-protocols-ciphers.html#secure-connections-supported-ciphers">Supported Protocols and Ciphers Between Viewers and CloudFront</a> in the <i>Amazon CloudFront Developer Guide</i>.</p><note>
    /// <p>On the CloudFront console, this setting is called <b>Security Policy</b>.</p>
    /// </note>
    /// <p>When you're using SNI only (you set <code>SSLSupportMethod</code> to <code>sni-only</code>), you must specify <code>TLSv1</code> or higher.</p>
    /// <p>If the distribution uses the CloudFront domain name such as <code>d111111abcdef8.cloudfront.net</code> (you set <code>CloudFrontDefaultCertificate</code> to <code>true</code>), CloudFront automatically sets the security policy to <code>TLSv1</code> regardless of the value that you set here.</p>
    pub fn minimum_protocol_version(&self) -> ::std::option::Option<&crate::types::MinimumProtocolVersion> {
        self.minimum_protocol_version.as_ref()
    }
    /// <p>This field is deprecated. Use one of the following fields instead:</p>
    /// <ul>
    /// <li>
    /// <p><code>ACMCertificateArn</code></p></li>
    /// <li>
    /// <p><code>IAMCertificateId</code></p></li>
    /// <li>
    /// <p><code>CloudFrontDefaultCertificate</code></p></li>
    /// </ul>
    #[deprecated]
    pub fn certificate(&self) -> ::std::option::Option<&str> {
        self.certificate.as_deref()
    }
    /// <p>This field is deprecated. Use one of the following fields instead:</p>
    /// <ul>
    /// <li>
    /// <p><code>ACMCertificateArn</code></p></li>
    /// <li>
    /// <p><code>IAMCertificateId</code></p></li>
    /// <li>
    /// <p><code>CloudFrontDefaultCertificate</code></p></li>
    /// </ul>
    #[deprecated]
    pub fn certificate_source(&self) -> ::std::option::Option<&crate::types::CertificateSource> {
        self.certificate_source.as_ref()
    }
}
impl ViewerCertificate {
    /// Creates a new builder-style object to manufacture [`ViewerCertificate`](crate::types::ViewerCertificate).
    pub fn builder() -> crate::types::builders::ViewerCertificateBuilder {
        crate::types::builders::ViewerCertificateBuilder::default()
    }
}

/// A builder for [`ViewerCertificate`](crate::types::ViewerCertificate).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ViewerCertificateBuilder {
    pub(crate) cloud_front_default_certificate: ::std::option::Option<bool>,
    pub(crate) iam_certificate_id: ::std::option::Option<::std::string::String>,
    pub(crate) acm_certificate_arn: ::std::option::Option<::std::string::String>,
    pub(crate) ssl_support_method: ::std::option::Option<crate::types::SslSupportMethod>,
    pub(crate) minimum_protocol_version: ::std::option::Option<crate::types::MinimumProtocolVersion>,
    pub(crate) certificate: ::std::option::Option<::std::string::String>,
    pub(crate) certificate_source: ::std::option::Option<crate::types::CertificateSource>,
}
impl ViewerCertificateBuilder {
    /// <p>If the distribution uses the CloudFront domain name such as <code>d111111abcdef8.cloudfront.net</code>, set this field to <code>true</code>.</p>
    /// <p>If the distribution uses <code>Aliases</code> (alternate domain names or CNAMEs), set this field to <code>false</code> and specify values for the following fields:</p>
    /// <ul>
    /// <li>
    /// <p><code>ACMCertificateArn</code> or <code>IAMCertificateId</code> (specify a value for one, not both)</p></li>
    /// <li>
    /// <p><code>MinimumProtocolVersion</code></p></li>
    /// <li>
    /// <p><code>SSLSupportMethod</code></p></li>
    /// </ul>
    pub fn cloud_front_default_certificate(mut self, input: bool) -> Self {
        self.cloud_front_default_certificate = ::std::option::Option::Some(input);
        self
    }
    /// <p>If the distribution uses the CloudFront domain name such as <code>d111111abcdef8.cloudfront.net</code>, set this field to <code>true</code>.</p>
    /// <p>If the distribution uses <code>Aliases</code> (alternate domain names or CNAMEs), set this field to <code>false</code> and specify values for the following fields:</p>
    /// <ul>
    /// <li>
    /// <p><code>ACMCertificateArn</code> or <code>IAMCertificateId</code> (specify a value for one, not both)</p></li>
    /// <li>
    /// <p><code>MinimumProtocolVersion</code></p></li>
    /// <li>
    /// <p><code>SSLSupportMethod</code></p></li>
    /// </ul>
    pub fn set_cloud_front_default_certificate(mut self, input: ::std::option::Option<bool>) -> Self {
        self.cloud_front_default_certificate = input;
        self
    }
    /// <p>If the distribution uses the CloudFront domain name such as <code>d111111abcdef8.cloudfront.net</code>, set this field to <code>true</code>.</p>
    /// <p>If the distribution uses <code>Aliases</code> (alternate domain names or CNAMEs), set this field to <code>false</code> and specify values for the following fields:</p>
    /// <ul>
    /// <li>
    /// <p><code>ACMCertificateArn</code> or <code>IAMCertificateId</code> (specify a value for one, not both)</p></li>
    /// <li>
    /// <p><code>MinimumProtocolVersion</code></p></li>
    /// <li>
    /// <p><code>SSLSupportMethod</code></p></li>
    /// </ul>
    pub fn get_cloud_front_default_certificate(&self) -> &::std::option::Option<bool> {
        &self.cloud_front_default_certificate
    }
    /// <p>If the distribution uses <code>Aliases</code> (alternate domain names or CNAMEs) and the SSL/TLS certificate is stored in <a href="https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_server-certs.html">Identity and Access Management (IAM)</a>, provide the ID of the IAM certificate.</p>
    /// <p>If you specify an IAM certificate ID, you must also specify values for <code>MinimumProtocolVersion</code> and <code>SSLSupportMethod</code>.</p>
    pub fn iam_certificate_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.iam_certificate_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>If the distribution uses <code>Aliases</code> (alternate domain names or CNAMEs) and the SSL/TLS certificate is stored in <a href="https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_server-certs.html">Identity and Access Management (IAM)</a>, provide the ID of the IAM certificate.</p>
    /// <p>If you specify an IAM certificate ID, you must also specify values for <code>MinimumProtocolVersion</code> and <code>SSLSupportMethod</code>.</p>
    pub fn set_iam_certificate_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.iam_certificate_id = input;
        self
    }
    /// <p>If the distribution uses <code>Aliases</code> (alternate domain names or CNAMEs) and the SSL/TLS certificate is stored in <a href="https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_server-certs.html">Identity and Access Management (IAM)</a>, provide the ID of the IAM certificate.</p>
    /// <p>If you specify an IAM certificate ID, you must also specify values for <code>MinimumProtocolVersion</code> and <code>SSLSupportMethod</code>.</p>
    pub fn get_iam_certificate_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.iam_certificate_id
    }
    /// <p>If the distribution uses <code>Aliases</code> (alternate domain names or CNAMEs) and the SSL/TLS certificate is stored in <a href="https://docs.aws.amazon.com/acm/latest/userguide/acm-overview.html">Certificate Manager (ACM)</a>, provide the Amazon Resource Name (ARN) of the ACM certificate. CloudFront only supports ACM certificates in the US East (N. Virginia) Region (<code>us-east-1</code>).</p>
    /// <p>If you specify an ACM certificate ARN, you must also specify values for <code>MinimumProtocolVersion</code> and <code>SSLSupportMethod</code>.</p>
    pub fn acm_certificate_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.acm_certificate_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>If the distribution uses <code>Aliases</code> (alternate domain names or CNAMEs) and the SSL/TLS certificate is stored in <a href="https://docs.aws.amazon.com/acm/latest/userguide/acm-overview.html">Certificate Manager (ACM)</a>, provide the Amazon Resource Name (ARN) of the ACM certificate. CloudFront only supports ACM certificates in the US East (N. Virginia) Region (<code>us-east-1</code>).</p>
    /// <p>If you specify an ACM certificate ARN, you must also specify values for <code>MinimumProtocolVersion</code> and <code>SSLSupportMethod</code>.</p>
    pub fn set_acm_certificate_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.acm_certificate_arn = input;
        self
    }
    /// <p>If the distribution uses <code>Aliases</code> (alternate domain names or CNAMEs) and the SSL/TLS certificate is stored in <a href="https://docs.aws.amazon.com/acm/latest/userguide/acm-overview.html">Certificate Manager (ACM)</a>, provide the Amazon Resource Name (ARN) of the ACM certificate. CloudFront only supports ACM certificates in the US East (N. Virginia) Region (<code>us-east-1</code>).</p>
    /// <p>If you specify an ACM certificate ARN, you must also specify values for <code>MinimumProtocolVersion</code> and <code>SSLSupportMethod</code>.</p>
    pub fn get_acm_certificate_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.acm_certificate_arn
    }
    /// <p>If the distribution uses <code>Aliases</code> (alternate domain names or CNAMEs), specify which viewers the distribution accepts HTTPS connections from.</p>
    /// <ul>
    /// <li>
    /// <p><code>sni-only</code> – The distribution accepts HTTPS connections from only viewers that support <a href="https://en.wikipedia.org/wiki/Server_Name_Indication">server name indication (SNI)</a>. This is recommended. Most browsers and clients support SNI.</p></li>
    /// <li>
    /// <p><code>vip</code> – The distribution accepts HTTPS connections from all viewers including those that don't support SNI. This is not recommended, and results in additional monthly charges from CloudFront.</p></li>
    /// <li>
    /// <p><code>static-ip</code> - Do not specify this value unless your distribution has been enabled for this feature by the CloudFront team. If you have a use case that requires static IP addresses for a distribution, contact CloudFront through the <a href="https://console.aws.amazon.com/support/home">Amazon Web ServicesSupport Center</a>.</p></li>
    /// </ul>
    /// <p>If the distribution uses the CloudFront domain name such as <code>d111111abcdef8.cloudfront.net</code>, don't set a value for this field.</p>
    pub fn ssl_support_method(mut self, input: crate::types::SslSupportMethod) -> Self {
        self.ssl_support_method = ::std::option::Option::Some(input);
        self
    }
    /// <p>If the distribution uses <code>Aliases</code> (alternate domain names or CNAMEs), specify which viewers the distribution accepts HTTPS connections from.</p>
    /// <ul>
    /// <li>
    /// <p><code>sni-only</code> – The distribution accepts HTTPS connections from only viewers that support <a href="https://en.wikipedia.org/wiki/Server_Name_Indication">server name indication (SNI)</a>. This is recommended. Most browsers and clients support SNI.</p></li>
    /// <li>
    /// <p><code>vip</code> – The distribution accepts HTTPS connections from all viewers including those that don't support SNI. This is not recommended, and results in additional monthly charges from CloudFront.</p></li>
    /// <li>
    /// <p><code>static-ip</code> - Do not specify this value unless your distribution has been enabled for this feature by the CloudFront team. If you have a use case that requires static IP addresses for a distribution, contact CloudFront through the <a href="https://console.aws.amazon.com/support/home">Amazon Web ServicesSupport Center</a>.</p></li>
    /// </ul>
    /// <p>If the distribution uses the CloudFront domain name such as <code>d111111abcdef8.cloudfront.net</code>, don't set a value for this field.</p>
    pub fn set_ssl_support_method(mut self, input: ::std::option::Option<crate::types::SslSupportMethod>) -> Self {
        self.ssl_support_method = input;
        self
    }
    /// <p>If the distribution uses <code>Aliases</code> (alternate domain names or CNAMEs), specify which viewers the distribution accepts HTTPS connections from.</p>
    /// <ul>
    /// <li>
    /// <p><code>sni-only</code> – The distribution accepts HTTPS connections from only viewers that support <a href="https://en.wikipedia.org/wiki/Server_Name_Indication">server name indication (SNI)</a>. This is recommended. Most browsers and clients support SNI.</p></li>
    /// <li>
    /// <p><code>vip</code> – The distribution accepts HTTPS connections from all viewers including those that don't support SNI. This is not recommended, and results in additional monthly charges from CloudFront.</p></li>
    /// <li>
    /// <p><code>static-ip</code> - Do not specify this value unless your distribution has been enabled for this feature by the CloudFront team. If you have a use case that requires static IP addresses for a distribution, contact CloudFront through the <a href="https://console.aws.amazon.com/support/home">Amazon Web ServicesSupport Center</a>.</p></li>
    /// </ul>
    /// <p>If the distribution uses the CloudFront domain name such as <code>d111111abcdef8.cloudfront.net</code>, don't set a value for this field.</p>
    pub fn get_ssl_support_method(&self) -> &::std::option::Option<crate::types::SslSupportMethod> {
        &self.ssl_support_method
    }
    /// <p>If the distribution uses <code>Aliases</code> (alternate domain names or CNAMEs), specify the security policy that you want CloudFront to use for HTTPS connections with viewers. The security policy determines two settings:</p>
    /// <ul>
    /// <li>
    /// <p>The minimum SSL/TLS protocol that CloudFront can use to communicate with viewers.</p></li>
    /// <li>
    /// <p>The ciphers that CloudFront can use to encrypt the content that it returns to viewers.</p></li>
    /// </ul>
    /// <p>For more information, see <a href="https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/distribution-web-values-specify.html#DownloadDistValues-security-policy">Security Policy</a> and <a href="https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/secure-connections-supported-viewer-protocols-ciphers.html#secure-connections-supported-ciphers">Supported Protocols and Ciphers Between Viewers and CloudFront</a> in the <i>Amazon CloudFront Developer Guide</i>.</p><note>
    /// <p>On the CloudFront console, this setting is called <b>Security Policy</b>.</p>
    /// </note>
    /// <p>When you're using SNI only (you set <code>SSLSupportMethod</code> to <code>sni-only</code>), you must specify <code>TLSv1</code> or higher.</p>
    /// <p>If the distribution uses the CloudFront domain name such as <code>d111111abcdef8.cloudfront.net</code> (you set <code>CloudFrontDefaultCertificate</code> to <code>true</code>), CloudFront automatically sets the security policy to <code>TLSv1</code> regardless of the value that you set here.</p>
    pub fn minimum_protocol_version(mut self, input: crate::types::MinimumProtocolVersion) -> Self {
        self.minimum_protocol_version = ::std::option::Option::Some(input);
        self
    }
    /// <p>If the distribution uses <code>Aliases</code> (alternate domain names or CNAMEs), specify the security policy that you want CloudFront to use for HTTPS connections with viewers. The security policy determines two settings:</p>
    /// <ul>
    /// <li>
    /// <p>The minimum SSL/TLS protocol that CloudFront can use to communicate with viewers.</p></li>
    /// <li>
    /// <p>The ciphers that CloudFront can use to encrypt the content that it returns to viewers.</p></li>
    /// </ul>
    /// <p>For more information, see <a href="https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/distribution-web-values-specify.html#DownloadDistValues-security-policy">Security Policy</a> and <a href="https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/secure-connections-supported-viewer-protocols-ciphers.html#secure-connections-supported-ciphers">Supported Protocols and Ciphers Between Viewers and CloudFront</a> in the <i>Amazon CloudFront Developer Guide</i>.</p><note>
    /// <p>On the CloudFront console, this setting is called <b>Security Policy</b>.</p>
    /// </note>
    /// <p>When you're using SNI only (you set <code>SSLSupportMethod</code> to <code>sni-only</code>), you must specify <code>TLSv1</code> or higher.</p>
    /// <p>If the distribution uses the CloudFront domain name such as <code>d111111abcdef8.cloudfront.net</code> (you set <code>CloudFrontDefaultCertificate</code> to <code>true</code>), CloudFront automatically sets the security policy to <code>TLSv1</code> regardless of the value that you set here.</p>
    pub fn set_minimum_protocol_version(mut self, input: ::std::option::Option<crate::types::MinimumProtocolVersion>) -> Self {
        self.minimum_protocol_version = input;
        self
    }
    /// <p>If the distribution uses <code>Aliases</code> (alternate domain names or CNAMEs), specify the security policy that you want CloudFront to use for HTTPS connections with viewers. The security policy determines two settings:</p>
    /// <ul>
    /// <li>
    /// <p>The minimum SSL/TLS protocol that CloudFront can use to communicate with viewers.</p></li>
    /// <li>
    /// <p>The ciphers that CloudFront can use to encrypt the content that it returns to viewers.</p></li>
    /// </ul>
    /// <p>For more information, see <a href="https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/distribution-web-values-specify.html#DownloadDistValues-security-policy">Security Policy</a> and <a href="https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/secure-connections-supported-viewer-protocols-ciphers.html#secure-connections-supported-ciphers">Supported Protocols and Ciphers Between Viewers and CloudFront</a> in the <i>Amazon CloudFront Developer Guide</i>.</p><note>
    /// <p>On the CloudFront console, this setting is called <b>Security Policy</b>.</p>
    /// </note>
    /// <p>When you're using SNI only (you set <code>SSLSupportMethod</code> to <code>sni-only</code>), you must specify <code>TLSv1</code> or higher.</p>
    /// <p>If the distribution uses the CloudFront domain name such as <code>d111111abcdef8.cloudfront.net</code> (you set <code>CloudFrontDefaultCertificate</code> to <code>true</code>), CloudFront automatically sets the security policy to <code>TLSv1</code> regardless of the value that you set here.</p>
    pub fn get_minimum_protocol_version(&self) -> &::std::option::Option<crate::types::MinimumProtocolVersion> {
        &self.minimum_protocol_version
    }
    /// <p>This field is deprecated. Use one of the following fields instead:</p>
    /// <ul>
    /// <li>
    /// <p><code>ACMCertificateArn</code></p></li>
    /// <li>
    /// <p><code>IAMCertificateId</code></p></li>
    /// <li>
    /// <p><code>CloudFrontDefaultCertificate</code></p></li>
    /// </ul>
    #[deprecated]
    pub fn certificate(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.certificate = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>This field is deprecated. Use one of the following fields instead:</p>
    /// <ul>
    /// <li>
    /// <p><code>ACMCertificateArn</code></p></li>
    /// <li>
    /// <p><code>IAMCertificateId</code></p></li>
    /// <li>
    /// <p><code>CloudFrontDefaultCertificate</code></p></li>
    /// </ul>
    #[deprecated]
    pub fn set_certificate(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.certificate = input;
        self
    }
    /// <p>This field is deprecated. Use one of the following fields instead:</p>
    /// <ul>
    /// <li>
    /// <p><code>ACMCertificateArn</code></p></li>
    /// <li>
    /// <p><code>IAMCertificateId</code></p></li>
    /// <li>
    /// <p><code>CloudFrontDefaultCertificate</code></p></li>
    /// </ul>
    #[deprecated]
    pub fn get_certificate(&self) -> &::std::option::Option<::std::string::String> {
        &self.certificate
    }
    /// <p>This field is deprecated. Use one of the following fields instead:</p>
    /// <ul>
    /// <li>
    /// <p><code>ACMCertificateArn</code></p></li>
    /// <li>
    /// <p><code>IAMCertificateId</code></p></li>
    /// <li>
    /// <p><code>CloudFrontDefaultCertificate</code></p></li>
    /// </ul>
    #[deprecated]
    pub fn certificate_source(mut self, input: crate::types::CertificateSource) -> Self {
        self.certificate_source = ::std::option::Option::Some(input);
        self
    }
    /// <p>This field is deprecated. Use one of the following fields instead:</p>
    /// <ul>
    /// <li>
    /// <p><code>ACMCertificateArn</code></p></li>
    /// <li>
    /// <p><code>IAMCertificateId</code></p></li>
    /// <li>
    /// <p><code>CloudFrontDefaultCertificate</code></p></li>
    /// </ul>
    #[deprecated]
    pub fn set_certificate_source(mut self, input: ::std::option::Option<crate::types::CertificateSource>) -> Self {
        self.certificate_source = input;
        self
    }
    /// <p>This field is deprecated. Use one of the following fields instead:</p>
    /// <ul>
    /// <li>
    /// <p><code>ACMCertificateArn</code></p></li>
    /// <li>
    /// <p><code>IAMCertificateId</code></p></li>
    /// <li>
    /// <p><code>CloudFrontDefaultCertificate</code></p></li>
    /// </ul>
    #[deprecated]
    pub fn get_certificate_source(&self) -> &::std::option::Option<crate::types::CertificateSource> {
        &self.certificate_source
    }
    /// Consumes the builder and constructs a [`ViewerCertificate`](crate::types::ViewerCertificate).
    pub fn build(self) -> crate::types::ViewerCertificate {
        crate::types::ViewerCertificate {
            cloud_front_default_certificate: self.cloud_front_default_certificate,
            iam_certificate_id: self.iam_certificate_id,
            acm_certificate_arn: self.acm_certificate_arn,
            ssl_support_method: self.ssl_support_method,
            minimum_protocol_version: self.minimum_protocol_version,
            certificate: self.certificate,
            certificate_source: self.certificate_source,
        }
    }
}

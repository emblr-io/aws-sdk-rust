// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Options to configure endpoint for the Elasticsearch domain.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DomainEndpointOptions {
    /// <p>Specify if only HTTPS endpoint should be enabled for the Elasticsearch domain.</p>
    pub enforce_https: ::std::option::Option<bool>,
    /// <p>Specify the TLS security policy that needs to be applied to the HTTPS endpoint of Elasticsearch domain. <br><br>
    /// It can be one of the following values:</p>
    /// <ul>
    /// <li><b>Policy-Min-TLS-1-0-2019-07: </b> TLS security policy that supports TLS version 1.0 to TLS version 1.2</li>
    /// <li><b>Policy-Min-TLS-1-2-2019-07: </b> TLS security policy that supports only TLS version 1.2</li>
    /// <li><b>Policy-Min-TLS-1-2-PFS-2023-10: </b> TLS security policy that supports TLS version 1.2 to TLS version 1.3 with perfect forward secrecy cipher suites</li>
    /// </ul>
    /// <p></p>
    pub tls_security_policy: ::std::option::Option<crate::types::TlsSecurityPolicy>,
    /// <p>Specify if custom endpoint should be enabled for the Elasticsearch domain.</p>
    pub custom_endpoint_enabled: ::std::option::Option<bool>,
    /// <p>Specify the fully qualified domain for your custom endpoint.</p>
    pub custom_endpoint: ::std::option::Option<::std::string::String>,
    /// <p>Specify ACM certificate ARN for your custom endpoint.</p>
    pub custom_endpoint_certificate_arn: ::std::option::Option<::std::string::String>,
}
impl DomainEndpointOptions {
    /// <p>Specify if only HTTPS endpoint should be enabled for the Elasticsearch domain.</p>
    pub fn enforce_https(&self) -> ::std::option::Option<bool> {
        self.enforce_https
    }
    /// <p>Specify the TLS security policy that needs to be applied to the HTTPS endpoint of Elasticsearch domain. <br><br>
    /// It can be one of the following values:</p>
    /// <ul>
    /// <li><b>Policy-Min-TLS-1-0-2019-07: </b> TLS security policy that supports TLS version 1.0 to TLS version 1.2</li>
    /// <li><b>Policy-Min-TLS-1-2-2019-07: </b> TLS security policy that supports only TLS version 1.2</li>
    /// <li><b>Policy-Min-TLS-1-2-PFS-2023-10: </b> TLS security policy that supports TLS version 1.2 to TLS version 1.3 with perfect forward secrecy cipher suites</li>
    /// </ul>
    /// <p></p>
    pub fn tls_security_policy(&self) -> ::std::option::Option<&crate::types::TlsSecurityPolicy> {
        self.tls_security_policy.as_ref()
    }
    /// <p>Specify if custom endpoint should be enabled for the Elasticsearch domain.</p>
    pub fn custom_endpoint_enabled(&self) -> ::std::option::Option<bool> {
        self.custom_endpoint_enabled
    }
    /// <p>Specify the fully qualified domain for your custom endpoint.</p>
    pub fn custom_endpoint(&self) -> ::std::option::Option<&str> {
        self.custom_endpoint.as_deref()
    }
    /// <p>Specify ACM certificate ARN for your custom endpoint.</p>
    pub fn custom_endpoint_certificate_arn(&self) -> ::std::option::Option<&str> {
        self.custom_endpoint_certificate_arn.as_deref()
    }
}
impl DomainEndpointOptions {
    /// Creates a new builder-style object to manufacture [`DomainEndpointOptions`](crate::types::DomainEndpointOptions).
    pub fn builder() -> crate::types::builders::DomainEndpointOptionsBuilder {
        crate::types::builders::DomainEndpointOptionsBuilder::default()
    }
}

/// A builder for [`DomainEndpointOptions`](crate::types::DomainEndpointOptions).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DomainEndpointOptionsBuilder {
    pub(crate) enforce_https: ::std::option::Option<bool>,
    pub(crate) tls_security_policy: ::std::option::Option<crate::types::TlsSecurityPolicy>,
    pub(crate) custom_endpoint_enabled: ::std::option::Option<bool>,
    pub(crate) custom_endpoint: ::std::option::Option<::std::string::String>,
    pub(crate) custom_endpoint_certificate_arn: ::std::option::Option<::std::string::String>,
}
impl DomainEndpointOptionsBuilder {
    /// <p>Specify if only HTTPS endpoint should be enabled for the Elasticsearch domain.</p>
    pub fn enforce_https(mut self, input: bool) -> Self {
        self.enforce_https = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specify if only HTTPS endpoint should be enabled for the Elasticsearch domain.</p>
    pub fn set_enforce_https(mut self, input: ::std::option::Option<bool>) -> Self {
        self.enforce_https = input;
        self
    }
    /// <p>Specify if only HTTPS endpoint should be enabled for the Elasticsearch domain.</p>
    pub fn get_enforce_https(&self) -> &::std::option::Option<bool> {
        &self.enforce_https
    }
    /// <p>Specify the TLS security policy that needs to be applied to the HTTPS endpoint of Elasticsearch domain. <br><br>
    /// It can be one of the following values:</p>
    /// <ul>
    /// <li><b>Policy-Min-TLS-1-0-2019-07: </b> TLS security policy that supports TLS version 1.0 to TLS version 1.2</li>
    /// <li><b>Policy-Min-TLS-1-2-2019-07: </b> TLS security policy that supports only TLS version 1.2</li>
    /// <li><b>Policy-Min-TLS-1-2-PFS-2023-10: </b> TLS security policy that supports TLS version 1.2 to TLS version 1.3 with perfect forward secrecy cipher suites</li>
    /// </ul>
    /// <p></p>
    pub fn tls_security_policy(mut self, input: crate::types::TlsSecurityPolicy) -> Self {
        self.tls_security_policy = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specify the TLS security policy that needs to be applied to the HTTPS endpoint of Elasticsearch domain. <br><br>
    /// It can be one of the following values:</p>
    /// <ul>
    /// <li><b>Policy-Min-TLS-1-0-2019-07: </b> TLS security policy that supports TLS version 1.0 to TLS version 1.2</li>
    /// <li><b>Policy-Min-TLS-1-2-2019-07: </b> TLS security policy that supports only TLS version 1.2</li>
    /// <li><b>Policy-Min-TLS-1-2-PFS-2023-10: </b> TLS security policy that supports TLS version 1.2 to TLS version 1.3 with perfect forward secrecy cipher suites</li>
    /// </ul>
    /// <p></p>
    pub fn set_tls_security_policy(mut self, input: ::std::option::Option<crate::types::TlsSecurityPolicy>) -> Self {
        self.tls_security_policy = input;
        self
    }
    /// <p>Specify the TLS security policy that needs to be applied to the HTTPS endpoint of Elasticsearch domain. <br><br>
    /// It can be one of the following values:</p>
    /// <ul>
    /// <li><b>Policy-Min-TLS-1-0-2019-07: </b> TLS security policy that supports TLS version 1.0 to TLS version 1.2</li>
    /// <li><b>Policy-Min-TLS-1-2-2019-07: </b> TLS security policy that supports only TLS version 1.2</li>
    /// <li><b>Policy-Min-TLS-1-2-PFS-2023-10: </b> TLS security policy that supports TLS version 1.2 to TLS version 1.3 with perfect forward secrecy cipher suites</li>
    /// </ul>
    /// <p></p>
    pub fn get_tls_security_policy(&self) -> &::std::option::Option<crate::types::TlsSecurityPolicy> {
        &self.tls_security_policy
    }
    /// <p>Specify if custom endpoint should be enabled for the Elasticsearch domain.</p>
    pub fn custom_endpoint_enabled(mut self, input: bool) -> Self {
        self.custom_endpoint_enabled = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specify if custom endpoint should be enabled for the Elasticsearch domain.</p>
    pub fn set_custom_endpoint_enabled(mut self, input: ::std::option::Option<bool>) -> Self {
        self.custom_endpoint_enabled = input;
        self
    }
    /// <p>Specify if custom endpoint should be enabled for the Elasticsearch domain.</p>
    pub fn get_custom_endpoint_enabled(&self) -> &::std::option::Option<bool> {
        &self.custom_endpoint_enabled
    }
    /// <p>Specify the fully qualified domain for your custom endpoint.</p>
    pub fn custom_endpoint(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.custom_endpoint = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Specify the fully qualified domain for your custom endpoint.</p>
    pub fn set_custom_endpoint(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.custom_endpoint = input;
        self
    }
    /// <p>Specify the fully qualified domain for your custom endpoint.</p>
    pub fn get_custom_endpoint(&self) -> &::std::option::Option<::std::string::String> {
        &self.custom_endpoint
    }
    /// <p>Specify ACM certificate ARN for your custom endpoint.</p>
    pub fn custom_endpoint_certificate_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.custom_endpoint_certificate_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Specify ACM certificate ARN for your custom endpoint.</p>
    pub fn set_custom_endpoint_certificate_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.custom_endpoint_certificate_arn = input;
        self
    }
    /// <p>Specify ACM certificate ARN for your custom endpoint.</p>
    pub fn get_custom_endpoint_certificate_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.custom_endpoint_certificate_arn
    }
    /// Consumes the builder and constructs a [`DomainEndpointOptions`](crate::types::DomainEndpointOptions).
    pub fn build(self) -> crate::types::DomainEndpointOptions {
        crate::types::DomainEndpointOptions {
            enforce_https: self.enforce_https,
            tls_security_policy: self.tls_security_policy,
            custom_endpoint_enabled: self.custom_endpoint_enabled,
            custom_endpoint: self.custom_endpoint,
            custom_endpoint_certificate_arn: self.custom_endpoint_certificate_arn,
        }
    }
}

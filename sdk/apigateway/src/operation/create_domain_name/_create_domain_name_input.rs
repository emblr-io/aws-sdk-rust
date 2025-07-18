// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>A request to create a new domain name.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CreateDomainNameInput {
    /// <p>The name of the DomainName resource.</p>
    pub domain_name: ::std::option::Option<::std::string::String>,
    /// <p>The user-friendly name of the certificate that will be used by edge-optimized endpoint or private endpoint for this domain name.</p>
    pub certificate_name: ::std::option::Option<::std::string::String>,
    /// <p>\[Deprecated\] The body of the server certificate that will be used by edge-optimized endpoint or private endpoint for this domain name provided by your certificate authority.</p>
    pub certificate_body: ::std::option::Option<::std::string::String>,
    /// <p>\[Deprecated\] Your edge-optimized endpoint's domain name certificate's private key.</p>
    pub certificate_private_key: ::std::option::Option<::std::string::String>,
    /// <p>\[Deprecated\] The intermediate certificates and optionally the root certificate, one after the other without any blank lines, used by an edge-optimized endpoint for this domain name. If you include the root certificate, your certificate chain must start with intermediate certificates and end with the root certificate. Use the intermediate certificates that were provided by your certificate authority. Do not include any intermediaries that are not in the chain of trust path.</p>
    pub certificate_chain: ::std::option::Option<::std::string::String>,
    /// <p>The reference to an Amazon Web Services-managed certificate that will be used by edge-optimized endpoint or private endpoint for this domain name. Certificate Manager is the only supported source.</p>
    pub certificate_arn: ::std::option::Option<::std::string::String>,
    /// <p>The user-friendly name of the certificate that will be used by regional endpoint for this domain name.</p>
    pub regional_certificate_name: ::std::option::Option<::std::string::String>,
    /// <p>The reference to an Amazon Web Services-managed certificate that will be used by regional endpoint for this domain name. Certificate Manager is the only supported source.</p>
    pub regional_certificate_arn: ::std::option::Option<::std::string::String>,
    /// <p>The endpoint configuration of this DomainName showing the endpoint types and IP address types of the domain name.</p>
    pub endpoint_configuration: ::std::option::Option<crate::types::EndpointConfiguration>,
    /// <p>The key-value map of strings. The valid character set is \[a-zA-Z+-=._:/\]. The tag key can be up to 128 characters and must not start with aws:. The tag value can be up to 256 characters.</p>
    pub tags: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    /// <p>The Transport Layer Security (TLS) version + cipher suite for this DomainName. The valid values are <code>TLS_1_0</code> and <code>TLS_1_2</code>.</p>
    pub security_policy: ::std::option::Option<crate::types::SecurityPolicy>,
    /// <p>The mutual TLS authentication configuration for a custom domain name. If specified, API Gateway performs two-way authentication between the client and the server. Clients must present a trusted certificate to access your API.</p>
    pub mutual_tls_authentication: ::std::option::Option<crate::types::MutualTlsAuthenticationInput>,
    /// <p>The ARN of the public certificate issued by ACM to validate ownership of your custom domain. Only required when configuring mutual TLS and using an ACM imported or private CA certificate ARN as the regionalCertificateArn.</p>
    pub ownership_verification_certificate_arn: ::std::option::Option<::std::string::String>,
    /// <p>A stringified JSON policy document that applies to the <code>execute-api</code> service for this DomainName regardless of the caller and Method configuration. Supported only for private custom domain names.</p>
    pub policy: ::std::option::Option<::std::string::String>,
    /// <p>The routing mode for this domain name. The routing mode determines how API Gateway sends traffic from your custom domain name to your private APIs.</p>
    pub routing_mode: ::std::option::Option<crate::types::RoutingMode>,
}
impl CreateDomainNameInput {
    /// <p>The name of the DomainName resource.</p>
    pub fn domain_name(&self) -> ::std::option::Option<&str> {
        self.domain_name.as_deref()
    }
    /// <p>The user-friendly name of the certificate that will be used by edge-optimized endpoint or private endpoint for this domain name.</p>
    pub fn certificate_name(&self) -> ::std::option::Option<&str> {
        self.certificate_name.as_deref()
    }
    /// <p>\[Deprecated\] The body of the server certificate that will be used by edge-optimized endpoint or private endpoint for this domain name provided by your certificate authority.</p>
    pub fn certificate_body(&self) -> ::std::option::Option<&str> {
        self.certificate_body.as_deref()
    }
    /// <p>\[Deprecated\] Your edge-optimized endpoint's domain name certificate's private key.</p>
    pub fn certificate_private_key(&self) -> ::std::option::Option<&str> {
        self.certificate_private_key.as_deref()
    }
    /// <p>\[Deprecated\] The intermediate certificates and optionally the root certificate, one after the other without any blank lines, used by an edge-optimized endpoint for this domain name. If you include the root certificate, your certificate chain must start with intermediate certificates and end with the root certificate. Use the intermediate certificates that were provided by your certificate authority. Do not include any intermediaries that are not in the chain of trust path.</p>
    pub fn certificate_chain(&self) -> ::std::option::Option<&str> {
        self.certificate_chain.as_deref()
    }
    /// <p>The reference to an Amazon Web Services-managed certificate that will be used by edge-optimized endpoint or private endpoint for this domain name. Certificate Manager is the only supported source.</p>
    pub fn certificate_arn(&self) -> ::std::option::Option<&str> {
        self.certificate_arn.as_deref()
    }
    /// <p>The user-friendly name of the certificate that will be used by regional endpoint for this domain name.</p>
    pub fn regional_certificate_name(&self) -> ::std::option::Option<&str> {
        self.regional_certificate_name.as_deref()
    }
    /// <p>The reference to an Amazon Web Services-managed certificate that will be used by regional endpoint for this domain name. Certificate Manager is the only supported source.</p>
    pub fn regional_certificate_arn(&self) -> ::std::option::Option<&str> {
        self.regional_certificate_arn.as_deref()
    }
    /// <p>The endpoint configuration of this DomainName showing the endpoint types and IP address types of the domain name.</p>
    pub fn endpoint_configuration(&self) -> ::std::option::Option<&crate::types::EndpointConfiguration> {
        self.endpoint_configuration.as_ref()
    }
    /// <p>The key-value map of strings. The valid character set is \[a-zA-Z+-=._:/\]. The tag key can be up to 128 characters and must not start with aws:. The tag value can be up to 256 characters.</p>
    pub fn tags(&self) -> ::std::option::Option<&::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        self.tags.as_ref()
    }
    /// <p>The Transport Layer Security (TLS) version + cipher suite for this DomainName. The valid values are <code>TLS_1_0</code> and <code>TLS_1_2</code>.</p>
    pub fn security_policy(&self) -> ::std::option::Option<&crate::types::SecurityPolicy> {
        self.security_policy.as_ref()
    }
    /// <p>The mutual TLS authentication configuration for a custom domain name. If specified, API Gateway performs two-way authentication between the client and the server. Clients must present a trusted certificate to access your API.</p>
    pub fn mutual_tls_authentication(&self) -> ::std::option::Option<&crate::types::MutualTlsAuthenticationInput> {
        self.mutual_tls_authentication.as_ref()
    }
    /// <p>The ARN of the public certificate issued by ACM to validate ownership of your custom domain. Only required when configuring mutual TLS and using an ACM imported or private CA certificate ARN as the regionalCertificateArn.</p>
    pub fn ownership_verification_certificate_arn(&self) -> ::std::option::Option<&str> {
        self.ownership_verification_certificate_arn.as_deref()
    }
    /// <p>A stringified JSON policy document that applies to the <code>execute-api</code> service for this DomainName regardless of the caller and Method configuration. Supported only for private custom domain names.</p>
    pub fn policy(&self) -> ::std::option::Option<&str> {
        self.policy.as_deref()
    }
    /// <p>The routing mode for this domain name. The routing mode determines how API Gateway sends traffic from your custom domain name to your private APIs.</p>
    pub fn routing_mode(&self) -> ::std::option::Option<&crate::types::RoutingMode> {
        self.routing_mode.as_ref()
    }
}
impl CreateDomainNameInput {
    /// Creates a new builder-style object to manufacture [`CreateDomainNameInput`](crate::operation::create_domain_name::CreateDomainNameInput).
    pub fn builder() -> crate::operation::create_domain_name::builders::CreateDomainNameInputBuilder {
        crate::operation::create_domain_name::builders::CreateDomainNameInputBuilder::default()
    }
}

/// A builder for [`CreateDomainNameInput`](crate::operation::create_domain_name::CreateDomainNameInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CreateDomainNameInputBuilder {
    pub(crate) domain_name: ::std::option::Option<::std::string::String>,
    pub(crate) certificate_name: ::std::option::Option<::std::string::String>,
    pub(crate) certificate_body: ::std::option::Option<::std::string::String>,
    pub(crate) certificate_private_key: ::std::option::Option<::std::string::String>,
    pub(crate) certificate_chain: ::std::option::Option<::std::string::String>,
    pub(crate) certificate_arn: ::std::option::Option<::std::string::String>,
    pub(crate) regional_certificate_name: ::std::option::Option<::std::string::String>,
    pub(crate) regional_certificate_arn: ::std::option::Option<::std::string::String>,
    pub(crate) endpoint_configuration: ::std::option::Option<crate::types::EndpointConfiguration>,
    pub(crate) tags: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    pub(crate) security_policy: ::std::option::Option<crate::types::SecurityPolicy>,
    pub(crate) mutual_tls_authentication: ::std::option::Option<crate::types::MutualTlsAuthenticationInput>,
    pub(crate) ownership_verification_certificate_arn: ::std::option::Option<::std::string::String>,
    pub(crate) policy: ::std::option::Option<::std::string::String>,
    pub(crate) routing_mode: ::std::option::Option<crate::types::RoutingMode>,
}
impl CreateDomainNameInputBuilder {
    /// <p>The name of the DomainName resource.</p>
    /// This field is required.
    pub fn domain_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.domain_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the DomainName resource.</p>
    pub fn set_domain_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.domain_name = input;
        self
    }
    /// <p>The name of the DomainName resource.</p>
    pub fn get_domain_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.domain_name
    }
    /// <p>The user-friendly name of the certificate that will be used by edge-optimized endpoint or private endpoint for this domain name.</p>
    pub fn certificate_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.certificate_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The user-friendly name of the certificate that will be used by edge-optimized endpoint or private endpoint for this domain name.</p>
    pub fn set_certificate_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.certificate_name = input;
        self
    }
    /// <p>The user-friendly name of the certificate that will be used by edge-optimized endpoint or private endpoint for this domain name.</p>
    pub fn get_certificate_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.certificate_name
    }
    /// <p>\[Deprecated\] The body of the server certificate that will be used by edge-optimized endpoint or private endpoint for this domain name provided by your certificate authority.</p>
    pub fn certificate_body(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.certificate_body = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>\[Deprecated\] The body of the server certificate that will be used by edge-optimized endpoint or private endpoint for this domain name provided by your certificate authority.</p>
    pub fn set_certificate_body(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.certificate_body = input;
        self
    }
    /// <p>\[Deprecated\] The body of the server certificate that will be used by edge-optimized endpoint or private endpoint for this domain name provided by your certificate authority.</p>
    pub fn get_certificate_body(&self) -> &::std::option::Option<::std::string::String> {
        &self.certificate_body
    }
    /// <p>\[Deprecated\] Your edge-optimized endpoint's domain name certificate's private key.</p>
    pub fn certificate_private_key(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.certificate_private_key = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>\[Deprecated\] Your edge-optimized endpoint's domain name certificate's private key.</p>
    pub fn set_certificate_private_key(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.certificate_private_key = input;
        self
    }
    /// <p>\[Deprecated\] Your edge-optimized endpoint's domain name certificate's private key.</p>
    pub fn get_certificate_private_key(&self) -> &::std::option::Option<::std::string::String> {
        &self.certificate_private_key
    }
    /// <p>\[Deprecated\] The intermediate certificates and optionally the root certificate, one after the other without any blank lines, used by an edge-optimized endpoint for this domain name. If you include the root certificate, your certificate chain must start with intermediate certificates and end with the root certificate. Use the intermediate certificates that were provided by your certificate authority. Do not include any intermediaries that are not in the chain of trust path.</p>
    pub fn certificate_chain(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.certificate_chain = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>\[Deprecated\] The intermediate certificates and optionally the root certificate, one after the other without any blank lines, used by an edge-optimized endpoint for this domain name. If you include the root certificate, your certificate chain must start with intermediate certificates and end with the root certificate. Use the intermediate certificates that were provided by your certificate authority. Do not include any intermediaries that are not in the chain of trust path.</p>
    pub fn set_certificate_chain(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.certificate_chain = input;
        self
    }
    /// <p>\[Deprecated\] The intermediate certificates and optionally the root certificate, one after the other without any blank lines, used by an edge-optimized endpoint for this domain name. If you include the root certificate, your certificate chain must start with intermediate certificates and end with the root certificate. Use the intermediate certificates that were provided by your certificate authority. Do not include any intermediaries that are not in the chain of trust path.</p>
    pub fn get_certificate_chain(&self) -> &::std::option::Option<::std::string::String> {
        &self.certificate_chain
    }
    /// <p>The reference to an Amazon Web Services-managed certificate that will be used by edge-optimized endpoint or private endpoint for this domain name. Certificate Manager is the only supported source.</p>
    pub fn certificate_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.certificate_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The reference to an Amazon Web Services-managed certificate that will be used by edge-optimized endpoint or private endpoint for this domain name. Certificate Manager is the only supported source.</p>
    pub fn set_certificate_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.certificate_arn = input;
        self
    }
    /// <p>The reference to an Amazon Web Services-managed certificate that will be used by edge-optimized endpoint or private endpoint for this domain name. Certificate Manager is the only supported source.</p>
    pub fn get_certificate_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.certificate_arn
    }
    /// <p>The user-friendly name of the certificate that will be used by regional endpoint for this domain name.</p>
    pub fn regional_certificate_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.regional_certificate_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The user-friendly name of the certificate that will be used by regional endpoint for this domain name.</p>
    pub fn set_regional_certificate_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.regional_certificate_name = input;
        self
    }
    /// <p>The user-friendly name of the certificate that will be used by regional endpoint for this domain name.</p>
    pub fn get_regional_certificate_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.regional_certificate_name
    }
    /// <p>The reference to an Amazon Web Services-managed certificate that will be used by regional endpoint for this domain name. Certificate Manager is the only supported source.</p>
    pub fn regional_certificate_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.regional_certificate_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The reference to an Amazon Web Services-managed certificate that will be used by regional endpoint for this domain name. Certificate Manager is the only supported source.</p>
    pub fn set_regional_certificate_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.regional_certificate_arn = input;
        self
    }
    /// <p>The reference to an Amazon Web Services-managed certificate that will be used by regional endpoint for this domain name. Certificate Manager is the only supported source.</p>
    pub fn get_regional_certificate_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.regional_certificate_arn
    }
    /// <p>The endpoint configuration of this DomainName showing the endpoint types and IP address types of the domain name.</p>
    pub fn endpoint_configuration(mut self, input: crate::types::EndpointConfiguration) -> Self {
        self.endpoint_configuration = ::std::option::Option::Some(input);
        self
    }
    /// <p>The endpoint configuration of this DomainName showing the endpoint types and IP address types of the domain name.</p>
    pub fn set_endpoint_configuration(mut self, input: ::std::option::Option<crate::types::EndpointConfiguration>) -> Self {
        self.endpoint_configuration = input;
        self
    }
    /// <p>The endpoint configuration of this DomainName showing the endpoint types and IP address types of the domain name.</p>
    pub fn get_endpoint_configuration(&self) -> &::std::option::Option<crate::types::EndpointConfiguration> {
        &self.endpoint_configuration
    }
    /// Adds a key-value pair to `tags`.
    ///
    /// To override the contents of this collection use [`set_tags`](Self::set_tags).
    ///
    /// <p>The key-value map of strings. The valid character set is \[a-zA-Z+-=._:/\]. The tag key can be up to 128 characters and must not start with aws:. The tag value can be up to 256 characters.</p>
    pub fn tags(mut self, k: impl ::std::convert::Into<::std::string::String>, v: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut hash_map = self.tags.unwrap_or_default();
        hash_map.insert(k.into(), v.into());
        self.tags = ::std::option::Option::Some(hash_map);
        self
    }
    /// <p>The key-value map of strings. The valid character set is \[a-zA-Z+-=._:/\]. The tag key can be up to 128 characters and must not start with aws:. The tag value can be up to 256 characters.</p>
    pub fn set_tags(mut self, input: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>) -> Self {
        self.tags = input;
        self
    }
    /// <p>The key-value map of strings. The valid character set is \[a-zA-Z+-=._:/\]. The tag key can be up to 128 characters and must not start with aws:. The tag value can be up to 256 characters.</p>
    pub fn get_tags(&self) -> &::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        &self.tags
    }
    /// <p>The Transport Layer Security (TLS) version + cipher suite for this DomainName. The valid values are <code>TLS_1_0</code> and <code>TLS_1_2</code>.</p>
    pub fn security_policy(mut self, input: crate::types::SecurityPolicy) -> Self {
        self.security_policy = ::std::option::Option::Some(input);
        self
    }
    /// <p>The Transport Layer Security (TLS) version + cipher suite for this DomainName. The valid values are <code>TLS_1_0</code> and <code>TLS_1_2</code>.</p>
    pub fn set_security_policy(mut self, input: ::std::option::Option<crate::types::SecurityPolicy>) -> Self {
        self.security_policy = input;
        self
    }
    /// <p>The Transport Layer Security (TLS) version + cipher suite for this DomainName. The valid values are <code>TLS_1_0</code> and <code>TLS_1_2</code>.</p>
    pub fn get_security_policy(&self) -> &::std::option::Option<crate::types::SecurityPolicy> {
        &self.security_policy
    }
    /// <p>The mutual TLS authentication configuration for a custom domain name. If specified, API Gateway performs two-way authentication between the client and the server. Clients must present a trusted certificate to access your API.</p>
    pub fn mutual_tls_authentication(mut self, input: crate::types::MutualTlsAuthenticationInput) -> Self {
        self.mutual_tls_authentication = ::std::option::Option::Some(input);
        self
    }
    /// <p>The mutual TLS authentication configuration for a custom domain name. If specified, API Gateway performs two-way authentication between the client and the server. Clients must present a trusted certificate to access your API.</p>
    pub fn set_mutual_tls_authentication(mut self, input: ::std::option::Option<crate::types::MutualTlsAuthenticationInput>) -> Self {
        self.mutual_tls_authentication = input;
        self
    }
    /// <p>The mutual TLS authentication configuration for a custom domain name. If specified, API Gateway performs two-way authentication between the client and the server. Clients must present a trusted certificate to access your API.</p>
    pub fn get_mutual_tls_authentication(&self) -> &::std::option::Option<crate::types::MutualTlsAuthenticationInput> {
        &self.mutual_tls_authentication
    }
    /// <p>The ARN of the public certificate issued by ACM to validate ownership of your custom domain. Only required when configuring mutual TLS and using an ACM imported or private CA certificate ARN as the regionalCertificateArn.</p>
    pub fn ownership_verification_certificate_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.ownership_verification_certificate_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ARN of the public certificate issued by ACM to validate ownership of your custom domain. Only required when configuring mutual TLS and using an ACM imported or private CA certificate ARN as the regionalCertificateArn.</p>
    pub fn set_ownership_verification_certificate_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.ownership_verification_certificate_arn = input;
        self
    }
    /// <p>The ARN of the public certificate issued by ACM to validate ownership of your custom domain. Only required when configuring mutual TLS and using an ACM imported or private CA certificate ARN as the regionalCertificateArn.</p>
    pub fn get_ownership_verification_certificate_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.ownership_verification_certificate_arn
    }
    /// <p>A stringified JSON policy document that applies to the <code>execute-api</code> service for this DomainName regardless of the caller and Method configuration. Supported only for private custom domain names.</p>
    pub fn policy(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.policy = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A stringified JSON policy document that applies to the <code>execute-api</code> service for this DomainName regardless of the caller and Method configuration. Supported only for private custom domain names.</p>
    pub fn set_policy(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.policy = input;
        self
    }
    /// <p>A stringified JSON policy document that applies to the <code>execute-api</code> service for this DomainName regardless of the caller and Method configuration. Supported only for private custom domain names.</p>
    pub fn get_policy(&self) -> &::std::option::Option<::std::string::String> {
        &self.policy
    }
    /// <p>The routing mode for this domain name. The routing mode determines how API Gateway sends traffic from your custom domain name to your private APIs.</p>
    pub fn routing_mode(mut self, input: crate::types::RoutingMode) -> Self {
        self.routing_mode = ::std::option::Option::Some(input);
        self
    }
    /// <p>The routing mode for this domain name. The routing mode determines how API Gateway sends traffic from your custom domain name to your private APIs.</p>
    pub fn set_routing_mode(mut self, input: ::std::option::Option<crate::types::RoutingMode>) -> Self {
        self.routing_mode = input;
        self
    }
    /// <p>The routing mode for this domain name. The routing mode determines how API Gateway sends traffic from your custom domain name to your private APIs.</p>
    pub fn get_routing_mode(&self) -> &::std::option::Option<crate::types::RoutingMode> {
        &self.routing_mode
    }
    /// Consumes the builder and constructs a [`CreateDomainNameInput`](crate::operation::create_domain_name::CreateDomainNameInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::create_domain_name::CreateDomainNameInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::create_domain_name::CreateDomainNameInput {
            domain_name: self.domain_name,
            certificate_name: self.certificate_name,
            certificate_body: self.certificate_body,
            certificate_private_key: self.certificate_private_key,
            certificate_chain: self.certificate_chain,
            certificate_arn: self.certificate_arn,
            regional_certificate_name: self.regional_certificate_name,
            regional_certificate_arn: self.regional_certificate_arn,
            endpoint_configuration: self.endpoint_configuration,
            tags: self.tags,
            security_policy: self.security_policy,
            mutual_tls_authentication: self.mutual_tls_authentication,
            ownership_verification_certificate_arn: self.ownership_verification_certificate_arn,
            policy: self.policy,
            routing_mode: self.routing_mode,
        })
    }
}

// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ModifyCustomDomainAssociationOutput {
    /// <p>The custom domain name associated with the result for the changed custom domain association.</p>
    pub custom_domain_name: ::std::option::Option<::std::string::String>,
    /// <p>The certificate Amazon Resource Name (ARN) associated with the result for the changed custom domain association.</p>
    pub custom_domain_certificate_arn: ::std::option::Option<::std::string::String>,
    /// <p>The identifier of the cluster associated with the result for the changed custom domain association.</p>
    pub cluster_identifier: ::std::option::Option<::std::string::String>,
    /// <p>The certificate expiration time associated with the result for the changed custom domain association.</p>
    pub custom_domain_cert_expiry_time: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl ModifyCustomDomainAssociationOutput {
    /// <p>The custom domain name associated with the result for the changed custom domain association.</p>
    pub fn custom_domain_name(&self) -> ::std::option::Option<&str> {
        self.custom_domain_name.as_deref()
    }
    /// <p>The certificate Amazon Resource Name (ARN) associated with the result for the changed custom domain association.</p>
    pub fn custom_domain_certificate_arn(&self) -> ::std::option::Option<&str> {
        self.custom_domain_certificate_arn.as_deref()
    }
    /// <p>The identifier of the cluster associated with the result for the changed custom domain association.</p>
    pub fn cluster_identifier(&self) -> ::std::option::Option<&str> {
        self.cluster_identifier.as_deref()
    }
    /// <p>The certificate expiration time associated with the result for the changed custom domain association.</p>
    pub fn custom_domain_cert_expiry_time(&self) -> ::std::option::Option<&str> {
        self.custom_domain_cert_expiry_time.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for ModifyCustomDomainAssociationOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl ModifyCustomDomainAssociationOutput {
    /// Creates a new builder-style object to manufacture [`ModifyCustomDomainAssociationOutput`](crate::operation::modify_custom_domain_association::ModifyCustomDomainAssociationOutput).
    pub fn builder() -> crate::operation::modify_custom_domain_association::builders::ModifyCustomDomainAssociationOutputBuilder {
        crate::operation::modify_custom_domain_association::builders::ModifyCustomDomainAssociationOutputBuilder::default()
    }
}

/// A builder for [`ModifyCustomDomainAssociationOutput`](crate::operation::modify_custom_domain_association::ModifyCustomDomainAssociationOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ModifyCustomDomainAssociationOutputBuilder {
    pub(crate) custom_domain_name: ::std::option::Option<::std::string::String>,
    pub(crate) custom_domain_certificate_arn: ::std::option::Option<::std::string::String>,
    pub(crate) cluster_identifier: ::std::option::Option<::std::string::String>,
    pub(crate) custom_domain_cert_expiry_time: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl ModifyCustomDomainAssociationOutputBuilder {
    /// <p>The custom domain name associated with the result for the changed custom domain association.</p>
    pub fn custom_domain_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.custom_domain_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The custom domain name associated with the result for the changed custom domain association.</p>
    pub fn set_custom_domain_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.custom_domain_name = input;
        self
    }
    /// <p>The custom domain name associated with the result for the changed custom domain association.</p>
    pub fn get_custom_domain_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.custom_domain_name
    }
    /// <p>The certificate Amazon Resource Name (ARN) associated with the result for the changed custom domain association.</p>
    pub fn custom_domain_certificate_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.custom_domain_certificate_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The certificate Amazon Resource Name (ARN) associated with the result for the changed custom domain association.</p>
    pub fn set_custom_domain_certificate_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.custom_domain_certificate_arn = input;
        self
    }
    /// <p>The certificate Amazon Resource Name (ARN) associated with the result for the changed custom domain association.</p>
    pub fn get_custom_domain_certificate_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.custom_domain_certificate_arn
    }
    /// <p>The identifier of the cluster associated with the result for the changed custom domain association.</p>
    pub fn cluster_identifier(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.cluster_identifier = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The identifier of the cluster associated with the result for the changed custom domain association.</p>
    pub fn set_cluster_identifier(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.cluster_identifier = input;
        self
    }
    /// <p>The identifier of the cluster associated with the result for the changed custom domain association.</p>
    pub fn get_cluster_identifier(&self) -> &::std::option::Option<::std::string::String> {
        &self.cluster_identifier
    }
    /// <p>The certificate expiration time associated with the result for the changed custom domain association.</p>
    pub fn custom_domain_cert_expiry_time(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.custom_domain_cert_expiry_time = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The certificate expiration time associated with the result for the changed custom domain association.</p>
    pub fn set_custom_domain_cert_expiry_time(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.custom_domain_cert_expiry_time = input;
        self
    }
    /// <p>The certificate expiration time associated with the result for the changed custom domain association.</p>
    pub fn get_custom_domain_cert_expiry_time(&self) -> &::std::option::Option<::std::string::String> {
        &self.custom_domain_cert_expiry_time
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`ModifyCustomDomainAssociationOutput`](crate::operation::modify_custom_domain_association::ModifyCustomDomainAssociationOutput).
    pub fn build(self) -> crate::operation::modify_custom_domain_association::ModifyCustomDomainAssociationOutput {
        crate::operation::modify_custom_domain_association::ModifyCustomDomainAssociationOutput {
            custom_domain_name: self.custom_domain_name,
            custom_domain_certificate_arn: self.custom_domain_certificate_arn,
            cluster_identifier: self.cluster_identifier,
            custom_domain_cert_expiry_time: self.custom_domain_cert_expiry_time,
            _request_id: self._request_id,
        }
    }
}

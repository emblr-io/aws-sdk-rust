// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ImportCrlInput {
    /// <p>The name of the certificate revocation list (CRL).</p>
    pub name: ::std::option::Option<::std::string::String>,
    /// <p>The x509 v3 specified certificate revocation list (CRL).</p>
    pub crl_data: ::std::option::Option<::aws_smithy_types::Blob>,
    /// <p>Specifies whether the certificate revocation list (CRL) is enabled.</p>
    pub enabled: ::std::option::Option<bool>,
    /// <p>A list of tags to attach to the certificate revocation list (CRL).</p>
    pub tags: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>,
    /// <p>The ARN of the TrustAnchor the certificate revocation list (CRL) will provide revocation for.</p>
    pub trust_anchor_arn: ::std::option::Option<::std::string::String>,
}
impl ImportCrlInput {
    /// <p>The name of the certificate revocation list (CRL).</p>
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
    /// <p>The x509 v3 specified certificate revocation list (CRL).</p>
    pub fn crl_data(&self) -> ::std::option::Option<&::aws_smithy_types::Blob> {
        self.crl_data.as_ref()
    }
    /// <p>Specifies whether the certificate revocation list (CRL) is enabled.</p>
    pub fn enabled(&self) -> ::std::option::Option<bool> {
        self.enabled
    }
    /// <p>A list of tags to attach to the certificate revocation list (CRL).</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.tags.is_none()`.
    pub fn tags(&self) -> &[crate::types::Tag] {
        self.tags.as_deref().unwrap_or_default()
    }
    /// <p>The ARN of the TrustAnchor the certificate revocation list (CRL) will provide revocation for.</p>
    pub fn trust_anchor_arn(&self) -> ::std::option::Option<&str> {
        self.trust_anchor_arn.as_deref()
    }
}
impl ImportCrlInput {
    /// Creates a new builder-style object to manufacture [`ImportCrlInput`](crate::operation::import_crl::ImportCrlInput).
    pub fn builder() -> crate::operation::import_crl::builders::ImportCrlInputBuilder {
        crate::operation::import_crl::builders::ImportCrlInputBuilder::default()
    }
}

/// A builder for [`ImportCrlInput`](crate::operation::import_crl::ImportCrlInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ImportCrlInputBuilder {
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) crl_data: ::std::option::Option<::aws_smithy_types::Blob>,
    pub(crate) enabled: ::std::option::Option<bool>,
    pub(crate) tags: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>,
    pub(crate) trust_anchor_arn: ::std::option::Option<::std::string::String>,
}
impl ImportCrlInputBuilder {
    /// <p>The name of the certificate revocation list (CRL).</p>
    /// This field is required.
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the certificate revocation list (CRL).</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The name of the certificate revocation list (CRL).</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// <p>The x509 v3 specified certificate revocation list (CRL).</p>
    /// This field is required.
    pub fn crl_data(mut self, input: ::aws_smithy_types::Blob) -> Self {
        self.crl_data = ::std::option::Option::Some(input);
        self
    }
    /// <p>The x509 v3 specified certificate revocation list (CRL).</p>
    pub fn set_crl_data(mut self, input: ::std::option::Option<::aws_smithy_types::Blob>) -> Self {
        self.crl_data = input;
        self
    }
    /// <p>The x509 v3 specified certificate revocation list (CRL).</p>
    pub fn get_crl_data(&self) -> &::std::option::Option<::aws_smithy_types::Blob> {
        &self.crl_data
    }
    /// <p>Specifies whether the certificate revocation list (CRL) is enabled.</p>
    pub fn enabled(mut self, input: bool) -> Self {
        self.enabled = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies whether the certificate revocation list (CRL) is enabled.</p>
    pub fn set_enabled(mut self, input: ::std::option::Option<bool>) -> Self {
        self.enabled = input;
        self
    }
    /// <p>Specifies whether the certificate revocation list (CRL) is enabled.</p>
    pub fn get_enabled(&self) -> &::std::option::Option<bool> {
        &self.enabled
    }
    /// Appends an item to `tags`.
    ///
    /// To override the contents of this collection use [`set_tags`](Self::set_tags).
    ///
    /// <p>A list of tags to attach to the certificate revocation list (CRL).</p>
    pub fn tags(mut self, input: crate::types::Tag) -> Self {
        let mut v = self.tags.unwrap_or_default();
        v.push(input);
        self.tags = ::std::option::Option::Some(v);
        self
    }
    /// <p>A list of tags to attach to the certificate revocation list (CRL).</p>
    pub fn set_tags(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>) -> Self {
        self.tags = input;
        self
    }
    /// <p>A list of tags to attach to the certificate revocation list (CRL).</p>
    pub fn get_tags(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::Tag>> {
        &self.tags
    }
    /// <p>The ARN of the TrustAnchor the certificate revocation list (CRL) will provide revocation for.</p>
    /// This field is required.
    pub fn trust_anchor_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.trust_anchor_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ARN of the TrustAnchor the certificate revocation list (CRL) will provide revocation for.</p>
    pub fn set_trust_anchor_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.trust_anchor_arn = input;
        self
    }
    /// <p>The ARN of the TrustAnchor the certificate revocation list (CRL) will provide revocation for.</p>
    pub fn get_trust_anchor_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.trust_anchor_arn
    }
    /// Consumes the builder and constructs a [`ImportCrlInput`](crate::operation::import_crl::ImportCrlInput).
    pub fn build(self) -> ::std::result::Result<crate::operation::import_crl::ImportCrlInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::import_crl::ImportCrlInput {
            name: self.name,
            crl_data: self.crl_data,
            enabled: self.enabled,
            tags: self.tags,
            trust_anchor_arn: self.trust_anchor_arn,
        })
    }
}

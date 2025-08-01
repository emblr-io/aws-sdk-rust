// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct TagCertificateAuthorityInput {
    /// <p>The Amazon Resource Name (ARN) that was returned when you called <a href="https://docs.aws.amazon.com/privateca/latest/APIReference/API_CreateCertificateAuthority.html">CreateCertificateAuthority</a>. This must be of the form:</p>
    /// <p><code>arn:aws:acm-pca:<i>region</i>:<i>account</i>:certificate-authority/<i>12345678-1234-1234-1234-123456789012</i> </code></p>
    pub certificate_authority_arn: ::std::option::Option<::std::string::String>,
    /// <p>List of tags to be associated with the CA.</p>
    pub tags: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>,
}
impl TagCertificateAuthorityInput {
    /// <p>The Amazon Resource Name (ARN) that was returned when you called <a href="https://docs.aws.amazon.com/privateca/latest/APIReference/API_CreateCertificateAuthority.html">CreateCertificateAuthority</a>. This must be of the form:</p>
    /// <p><code>arn:aws:acm-pca:<i>region</i>:<i>account</i>:certificate-authority/<i>12345678-1234-1234-1234-123456789012</i> </code></p>
    pub fn certificate_authority_arn(&self) -> ::std::option::Option<&str> {
        self.certificate_authority_arn.as_deref()
    }
    /// <p>List of tags to be associated with the CA.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.tags.is_none()`.
    pub fn tags(&self) -> &[crate::types::Tag] {
        self.tags.as_deref().unwrap_or_default()
    }
}
impl TagCertificateAuthorityInput {
    /// Creates a new builder-style object to manufacture [`TagCertificateAuthorityInput`](crate::operation::tag_certificate_authority::TagCertificateAuthorityInput).
    pub fn builder() -> crate::operation::tag_certificate_authority::builders::TagCertificateAuthorityInputBuilder {
        crate::operation::tag_certificate_authority::builders::TagCertificateAuthorityInputBuilder::default()
    }
}

/// A builder for [`TagCertificateAuthorityInput`](crate::operation::tag_certificate_authority::TagCertificateAuthorityInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct TagCertificateAuthorityInputBuilder {
    pub(crate) certificate_authority_arn: ::std::option::Option<::std::string::String>,
    pub(crate) tags: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>,
}
impl TagCertificateAuthorityInputBuilder {
    /// <p>The Amazon Resource Name (ARN) that was returned when you called <a href="https://docs.aws.amazon.com/privateca/latest/APIReference/API_CreateCertificateAuthority.html">CreateCertificateAuthority</a>. This must be of the form:</p>
    /// <p><code>arn:aws:acm-pca:<i>region</i>:<i>account</i>:certificate-authority/<i>12345678-1234-1234-1234-123456789012</i> </code></p>
    /// This field is required.
    pub fn certificate_authority_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.certificate_authority_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) that was returned when you called <a href="https://docs.aws.amazon.com/privateca/latest/APIReference/API_CreateCertificateAuthority.html">CreateCertificateAuthority</a>. This must be of the form:</p>
    /// <p><code>arn:aws:acm-pca:<i>region</i>:<i>account</i>:certificate-authority/<i>12345678-1234-1234-1234-123456789012</i> </code></p>
    pub fn set_certificate_authority_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.certificate_authority_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) that was returned when you called <a href="https://docs.aws.amazon.com/privateca/latest/APIReference/API_CreateCertificateAuthority.html">CreateCertificateAuthority</a>. This must be of the form:</p>
    /// <p><code>arn:aws:acm-pca:<i>region</i>:<i>account</i>:certificate-authority/<i>12345678-1234-1234-1234-123456789012</i> </code></p>
    pub fn get_certificate_authority_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.certificate_authority_arn
    }
    /// Appends an item to `tags`.
    ///
    /// To override the contents of this collection use [`set_tags`](Self::set_tags).
    ///
    /// <p>List of tags to be associated with the CA.</p>
    pub fn tags(mut self, input: crate::types::Tag) -> Self {
        let mut v = self.tags.unwrap_or_default();
        v.push(input);
        self.tags = ::std::option::Option::Some(v);
        self
    }
    /// <p>List of tags to be associated with the CA.</p>
    pub fn set_tags(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>) -> Self {
        self.tags = input;
        self
    }
    /// <p>List of tags to be associated with the CA.</p>
    pub fn get_tags(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::Tag>> {
        &self.tags
    }
    /// Consumes the builder and constructs a [`TagCertificateAuthorityInput`](crate::operation::tag_certificate_authority::TagCertificateAuthorityInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::tag_certificate_authority::TagCertificateAuthorityInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::tag_certificate_authority::TagCertificateAuthorityInput {
            certificate_authority_arn: self.certificate_authority_arn,
            tags: self.tags,
        })
    }
}

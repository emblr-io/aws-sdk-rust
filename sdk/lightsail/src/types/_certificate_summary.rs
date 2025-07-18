// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Describes an Amazon Lightsail SSL/TLS certificate.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CertificateSummary {
    /// <p>The Amazon Resource Name (ARN) of the certificate.</p>
    pub certificate_arn: ::std::option::Option<::std::string::String>,
    /// <p>The name of the certificate.</p>
    pub certificate_name: ::std::option::Option<::std::string::String>,
    /// <p>The domain name of the certificate.</p>
    pub domain_name: ::std::option::Option<::std::string::String>,
    /// <p>An object that describes a certificate in detail.</p>
    pub certificate_detail: ::std::option::Option<crate::types::Certificate>,
    /// <p>The tag keys and optional values for the resource. For more information about tags in Lightsail, see the <a href="https://docs.aws.amazon.com/lightsail/latest/userguide/amazon-lightsail-tags">Amazon Lightsail Developer Guide</a>.</p>
    pub tags: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>,
}
impl CertificateSummary {
    /// <p>The Amazon Resource Name (ARN) of the certificate.</p>
    pub fn certificate_arn(&self) -> ::std::option::Option<&str> {
        self.certificate_arn.as_deref()
    }
    /// <p>The name of the certificate.</p>
    pub fn certificate_name(&self) -> ::std::option::Option<&str> {
        self.certificate_name.as_deref()
    }
    /// <p>The domain name of the certificate.</p>
    pub fn domain_name(&self) -> ::std::option::Option<&str> {
        self.domain_name.as_deref()
    }
    /// <p>An object that describes a certificate in detail.</p>
    pub fn certificate_detail(&self) -> ::std::option::Option<&crate::types::Certificate> {
        self.certificate_detail.as_ref()
    }
    /// <p>The tag keys and optional values for the resource. For more information about tags in Lightsail, see the <a href="https://docs.aws.amazon.com/lightsail/latest/userguide/amazon-lightsail-tags">Amazon Lightsail Developer Guide</a>.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.tags.is_none()`.
    pub fn tags(&self) -> &[crate::types::Tag] {
        self.tags.as_deref().unwrap_or_default()
    }
}
impl CertificateSummary {
    /// Creates a new builder-style object to manufacture [`CertificateSummary`](crate::types::CertificateSummary).
    pub fn builder() -> crate::types::builders::CertificateSummaryBuilder {
        crate::types::builders::CertificateSummaryBuilder::default()
    }
}

/// A builder for [`CertificateSummary`](crate::types::CertificateSummary).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CertificateSummaryBuilder {
    pub(crate) certificate_arn: ::std::option::Option<::std::string::String>,
    pub(crate) certificate_name: ::std::option::Option<::std::string::String>,
    pub(crate) domain_name: ::std::option::Option<::std::string::String>,
    pub(crate) certificate_detail: ::std::option::Option<crate::types::Certificate>,
    pub(crate) tags: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>,
}
impl CertificateSummaryBuilder {
    /// <p>The Amazon Resource Name (ARN) of the certificate.</p>
    pub fn certificate_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.certificate_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the certificate.</p>
    pub fn set_certificate_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.certificate_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the certificate.</p>
    pub fn get_certificate_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.certificate_arn
    }
    /// <p>The name of the certificate.</p>
    pub fn certificate_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.certificate_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the certificate.</p>
    pub fn set_certificate_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.certificate_name = input;
        self
    }
    /// <p>The name of the certificate.</p>
    pub fn get_certificate_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.certificate_name
    }
    /// <p>The domain name of the certificate.</p>
    pub fn domain_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.domain_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The domain name of the certificate.</p>
    pub fn set_domain_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.domain_name = input;
        self
    }
    /// <p>The domain name of the certificate.</p>
    pub fn get_domain_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.domain_name
    }
    /// <p>An object that describes a certificate in detail.</p>
    pub fn certificate_detail(mut self, input: crate::types::Certificate) -> Self {
        self.certificate_detail = ::std::option::Option::Some(input);
        self
    }
    /// <p>An object that describes a certificate in detail.</p>
    pub fn set_certificate_detail(mut self, input: ::std::option::Option<crate::types::Certificate>) -> Self {
        self.certificate_detail = input;
        self
    }
    /// <p>An object that describes a certificate in detail.</p>
    pub fn get_certificate_detail(&self) -> &::std::option::Option<crate::types::Certificate> {
        &self.certificate_detail
    }
    /// Appends an item to `tags`.
    ///
    /// To override the contents of this collection use [`set_tags`](Self::set_tags).
    ///
    /// <p>The tag keys and optional values for the resource. For more information about tags in Lightsail, see the <a href="https://docs.aws.amazon.com/lightsail/latest/userguide/amazon-lightsail-tags">Amazon Lightsail Developer Guide</a>.</p>
    pub fn tags(mut self, input: crate::types::Tag) -> Self {
        let mut v = self.tags.unwrap_or_default();
        v.push(input);
        self.tags = ::std::option::Option::Some(v);
        self
    }
    /// <p>The tag keys and optional values for the resource. For more information about tags in Lightsail, see the <a href="https://docs.aws.amazon.com/lightsail/latest/userguide/amazon-lightsail-tags">Amazon Lightsail Developer Guide</a>.</p>
    pub fn set_tags(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>) -> Self {
        self.tags = input;
        self
    }
    /// <p>The tag keys and optional values for the resource. For more information about tags in Lightsail, see the <a href="https://docs.aws.amazon.com/lightsail/latest/userguide/amazon-lightsail-tags">Amazon Lightsail Developer Guide</a>.</p>
    pub fn get_tags(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::Tag>> {
        &self.tags
    }
    /// Consumes the builder and constructs a [`CertificateSummary`](crate::types::CertificateSummary).
    pub fn build(self) -> crate::types::CertificateSummary {
        crate::types::CertificateSummary {
            certificate_arn: self.certificate_arn,
            certificate_name: self.certificate_name,
            domain_name: self.domain_name,
            certificate_detail: self.certificate_detail,
            tags: self.tags,
        }
    }
}

// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct AddTagsToCertificateInput {
    /// <p>String that contains the ARN of the ACM certificate to which the tag is to be applied. This must be of the form:</p>
    /// <p><code>arn:aws:acm:region:123456789012:certificate/12345678-1234-1234-1234-123456789012</code></p>
    /// <p>For more information about ARNs, see <a href="https://docs.aws.amazon.com/general/latest/gr/aws-arns-and-namespaces.html">Amazon Resource Names (ARNs)</a>.</p>
    pub certificate_arn: ::std::option::Option<::std::string::String>,
    /// <p>The key-value pair that defines the tag. The tag value is optional.</p>
    pub tags: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>,
}
impl AddTagsToCertificateInput {
    /// <p>String that contains the ARN of the ACM certificate to which the tag is to be applied. This must be of the form:</p>
    /// <p><code>arn:aws:acm:region:123456789012:certificate/12345678-1234-1234-1234-123456789012</code></p>
    /// <p>For more information about ARNs, see <a href="https://docs.aws.amazon.com/general/latest/gr/aws-arns-and-namespaces.html">Amazon Resource Names (ARNs)</a>.</p>
    pub fn certificate_arn(&self) -> ::std::option::Option<&str> {
        self.certificate_arn.as_deref()
    }
    /// <p>The key-value pair that defines the tag. The tag value is optional.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.tags.is_none()`.
    pub fn tags(&self) -> &[crate::types::Tag] {
        self.tags.as_deref().unwrap_or_default()
    }
}
impl AddTagsToCertificateInput {
    /// Creates a new builder-style object to manufacture [`AddTagsToCertificateInput`](crate::operation::add_tags_to_certificate::AddTagsToCertificateInput).
    pub fn builder() -> crate::operation::add_tags_to_certificate::builders::AddTagsToCertificateInputBuilder {
        crate::operation::add_tags_to_certificate::builders::AddTagsToCertificateInputBuilder::default()
    }
}

/// A builder for [`AddTagsToCertificateInput`](crate::operation::add_tags_to_certificate::AddTagsToCertificateInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct AddTagsToCertificateInputBuilder {
    pub(crate) certificate_arn: ::std::option::Option<::std::string::String>,
    pub(crate) tags: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>,
}
impl AddTagsToCertificateInputBuilder {
    /// <p>String that contains the ARN of the ACM certificate to which the tag is to be applied. This must be of the form:</p>
    /// <p><code>arn:aws:acm:region:123456789012:certificate/12345678-1234-1234-1234-123456789012</code></p>
    /// <p>For more information about ARNs, see <a href="https://docs.aws.amazon.com/general/latest/gr/aws-arns-and-namespaces.html">Amazon Resource Names (ARNs)</a>.</p>
    /// This field is required.
    pub fn certificate_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.certificate_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>String that contains the ARN of the ACM certificate to which the tag is to be applied. This must be of the form:</p>
    /// <p><code>arn:aws:acm:region:123456789012:certificate/12345678-1234-1234-1234-123456789012</code></p>
    /// <p>For more information about ARNs, see <a href="https://docs.aws.amazon.com/general/latest/gr/aws-arns-and-namespaces.html">Amazon Resource Names (ARNs)</a>.</p>
    pub fn set_certificate_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.certificate_arn = input;
        self
    }
    /// <p>String that contains the ARN of the ACM certificate to which the tag is to be applied. This must be of the form:</p>
    /// <p><code>arn:aws:acm:region:123456789012:certificate/12345678-1234-1234-1234-123456789012</code></p>
    /// <p>For more information about ARNs, see <a href="https://docs.aws.amazon.com/general/latest/gr/aws-arns-and-namespaces.html">Amazon Resource Names (ARNs)</a>.</p>
    pub fn get_certificate_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.certificate_arn
    }
    /// Appends an item to `tags`.
    ///
    /// To override the contents of this collection use [`set_tags`](Self::set_tags).
    ///
    /// <p>The key-value pair that defines the tag. The tag value is optional.</p>
    pub fn tags(mut self, input: crate::types::Tag) -> Self {
        let mut v = self.tags.unwrap_or_default();
        v.push(input);
        self.tags = ::std::option::Option::Some(v);
        self
    }
    /// <p>The key-value pair that defines the tag. The tag value is optional.</p>
    pub fn set_tags(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>) -> Self {
        self.tags = input;
        self
    }
    /// <p>The key-value pair that defines the tag. The tag value is optional.</p>
    pub fn get_tags(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::Tag>> {
        &self.tags
    }
    /// Consumes the builder and constructs a [`AddTagsToCertificateInput`](crate::operation::add_tags_to_certificate::AddTagsToCertificateInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::add_tags_to_certificate::AddTagsToCertificateInput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::add_tags_to_certificate::AddTagsToCertificateInput {
            certificate_arn: self.certificate_arn,
            tags: self.tags,
        })
    }
}

// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct RemoveTagsFromCertificateInput {
    /// <p>String that contains the ARN of the ACM Certificate with one or more tags that you want to remove. This must be of the form:</p>
    /// <p><code>arn:aws:acm:region:123456789012:certificate/12345678-1234-1234-1234-123456789012</code></p>
    /// <p>For more information about ARNs, see <a href="https://docs.aws.amazon.com/general/latest/gr/aws-arns-and-namespaces.html">Amazon Resource Names (ARNs)</a>.</p>
    pub certificate_arn: ::std::option::Option<::std::string::String>,
    /// <p>The key-value pair that defines the tag to remove.</p>
    pub tags: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>,
}
impl RemoveTagsFromCertificateInput {
    /// <p>String that contains the ARN of the ACM Certificate with one or more tags that you want to remove. This must be of the form:</p>
    /// <p><code>arn:aws:acm:region:123456789012:certificate/12345678-1234-1234-1234-123456789012</code></p>
    /// <p>For more information about ARNs, see <a href="https://docs.aws.amazon.com/general/latest/gr/aws-arns-and-namespaces.html">Amazon Resource Names (ARNs)</a>.</p>
    pub fn certificate_arn(&self) -> ::std::option::Option<&str> {
        self.certificate_arn.as_deref()
    }
    /// <p>The key-value pair that defines the tag to remove.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.tags.is_none()`.
    pub fn tags(&self) -> &[crate::types::Tag] {
        self.tags.as_deref().unwrap_or_default()
    }
}
impl RemoveTagsFromCertificateInput {
    /// Creates a new builder-style object to manufacture [`RemoveTagsFromCertificateInput`](crate::operation::remove_tags_from_certificate::RemoveTagsFromCertificateInput).
    pub fn builder() -> crate::operation::remove_tags_from_certificate::builders::RemoveTagsFromCertificateInputBuilder {
        crate::operation::remove_tags_from_certificate::builders::RemoveTagsFromCertificateInputBuilder::default()
    }
}

/// A builder for [`RemoveTagsFromCertificateInput`](crate::operation::remove_tags_from_certificate::RemoveTagsFromCertificateInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct RemoveTagsFromCertificateInputBuilder {
    pub(crate) certificate_arn: ::std::option::Option<::std::string::String>,
    pub(crate) tags: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>,
}
impl RemoveTagsFromCertificateInputBuilder {
    /// <p>String that contains the ARN of the ACM Certificate with one or more tags that you want to remove. This must be of the form:</p>
    /// <p><code>arn:aws:acm:region:123456789012:certificate/12345678-1234-1234-1234-123456789012</code></p>
    /// <p>For more information about ARNs, see <a href="https://docs.aws.amazon.com/general/latest/gr/aws-arns-and-namespaces.html">Amazon Resource Names (ARNs)</a>.</p>
    /// This field is required.
    pub fn certificate_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.certificate_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>String that contains the ARN of the ACM Certificate with one or more tags that you want to remove. This must be of the form:</p>
    /// <p><code>arn:aws:acm:region:123456789012:certificate/12345678-1234-1234-1234-123456789012</code></p>
    /// <p>For more information about ARNs, see <a href="https://docs.aws.amazon.com/general/latest/gr/aws-arns-and-namespaces.html">Amazon Resource Names (ARNs)</a>.</p>
    pub fn set_certificate_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.certificate_arn = input;
        self
    }
    /// <p>String that contains the ARN of the ACM Certificate with one or more tags that you want to remove. This must be of the form:</p>
    /// <p><code>arn:aws:acm:region:123456789012:certificate/12345678-1234-1234-1234-123456789012</code></p>
    /// <p>For more information about ARNs, see <a href="https://docs.aws.amazon.com/general/latest/gr/aws-arns-and-namespaces.html">Amazon Resource Names (ARNs)</a>.</p>
    pub fn get_certificate_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.certificate_arn
    }
    /// Appends an item to `tags`.
    ///
    /// To override the contents of this collection use [`set_tags`](Self::set_tags).
    ///
    /// <p>The key-value pair that defines the tag to remove.</p>
    pub fn tags(mut self, input: crate::types::Tag) -> Self {
        let mut v = self.tags.unwrap_or_default();
        v.push(input);
        self.tags = ::std::option::Option::Some(v);
        self
    }
    /// <p>The key-value pair that defines the tag to remove.</p>
    pub fn set_tags(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>) -> Self {
        self.tags = input;
        self
    }
    /// <p>The key-value pair that defines the tag to remove.</p>
    pub fn get_tags(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::Tag>> {
        &self.tags
    }
    /// Consumes the builder and constructs a [`RemoveTagsFromCertificateInput`](crate::operation::remove_tags_from_certificate::RemoveTagsFromCertificateInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::remove_tags_from_certificate::RemoveTagsFromCertificateInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::remove_tags_from_certificate::RemoveTagsFromCertificateInput {
            certificate_arn: self.certificate_arn,
            tags: self.tags,
        })
    }
}

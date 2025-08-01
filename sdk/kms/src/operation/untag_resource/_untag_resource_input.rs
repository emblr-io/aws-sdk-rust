// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct UntagResourceInput {
    /// <p>Identifies the KMS key from which you are removing tags.</p>
    /// <p>Specify the key ID or key ARN of the KMS key.</p>
    /// <p>For example:</p>
    /// <ul>
    /// <li>
    /// <p>Key ID: <code>1234abcd-12ab-34cd-56ef-1234567890ab</code></p></li>
    /// <li>
    /// <p>Key ARN: <code>arn:aws:kms:us-east-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab</code></p></li>
    /// </ul>
    /// <p>To get the key ID and key ARN for a KMS key, use <code>ListKeys</code> or <code>DescribeKey</code>.</p>
    pub key_id: ::std::option::Option<::std::string::String>,
    /// <p>One or more tag keys. Specify only the tag keys, not the tag values.</p>
    pub tag_keys: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl UntagResourceInput {
    /// <p>Identifies the KMS key from which you are removing tags.</p>
    /// <p>Specify the key ID or key ARN of the KMS key.</p>
    /// <p>For example:</p>
    /// <ul>
    /// <li>
    /// <p>Key ID: <code>1234abcd-12ab-34cd-56ef-1234567890ab</code></p></li>
    /// <li>
    /// <p>Key ARN: <code>arn:aws:kms:us-east-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab</code></p></li>
    /// </ul>
    /// <p>To get the key ID and key ARN for a KMS key, use <code>ListKeys</code> or <code>DescribeKey</code>.</p>
    pub fn key_id(&self) -> ::std::option::Option<&str> {
        self.key_id.as_deref()
    }
    /// <p>One or more tag keys. Specify only the tag keys, not the tag values.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.tag_keys.is_none()`.
    pub fn tag_keys(&self) -> &[::std::string::String] {
        self.tag_keys.as_deref().unwrap_or_default()
    }
}
impl UntagResourceInput {
    /// Creates a new builder-style object to manufacture [`UntagResourceInput`](crate::operation::untag_resource::UntagResourceInput).
    pub fn builder() -> crate::operation::untag_resource::builders::UntagResourceInputBuilder {
        crate::operation::untag_resource::builders::UntagResourceInputBuilder::default()
    }
}

/// A builder for [`UntagResourceInput`](crate::operation::untag_resource::UntagResourceInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct UntagResourceInputBuilder {
    pub(crate) key_id: ::std::option::Option<::std::string::String>,
    pub(crate) tag_keys: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl UntagResourceInputBuilder {
    /// <p>Identifies the KMS key from which you are removing tags.</p>
    /// <p>Specify the key ID or key ARN of the KMS key.</p>
    /// <p>For example:</p>
    /// <ul>
    /// <li>
    /// <p>Key ID: <code>1234abcd-12ab-34cd-56ef-1234567890ab</code></p></li>
    /// <li>
    /// <p>Key ARN: <code>arn:aws:kms:us-east-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab</code></p></li>
    /// </ul>
    /// <p>To get the key ID and key ARN for a KMS key, use <code>ListKeys</code> or <code>DescribeKey</code>.</p>
    /// This field is required.
    pub fn key_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.key_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Identifies the KMS key from which you are removing tags.</p>
    /// <p>Specify the key ID or key ARN of the KMS key.</p>
    /// <p>For example:</p>
    /// <ul>
    /// <li>
    /// <p>Key ID: <code>1234abcd-12ab-34cd-56ef-1234567890ab</code></p></li>
    /// <li>
    /// <p>Key ARN: <code>arn:aws:kms:us-east-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab</code></p></li>
    /// </ul>
    /// <p>To get the key ID and key ARN for a KMS key, use <code>ListKeys</code> or <code>DescribeKey</code>.</p>
    pub fn set_key_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.key_id = input;
        self
    }
    /// <p>Identifies the KMS key from which you are removing tags.</p>
    /// <p>Specify the key ID or key ARN of the KMS key.</p>
    /// <p>For example:</p>
    /// <ul>
    /// <li>
    /// <p>Key ID: <code>1234abcd-12ab-34cd-56ef-1234567890ab</code></p></li>
    /// <li>
    /// <p>Key ARN: <code>arn:aws:kms:us-east-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab</code></p></li>
    /// </ul>
    /// <p>To get the key ID and key ARN for a KMS key, use <code>ListKeys</code> or <code>DescribeKey</code>.</p>
    pub fn get_key_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.key_id
    }
    /// Appends an item to `tag_keys`.
    ///
    /// To override the contents of this collection use [`set_tag_keys`](Self::set_tag_keys).
    ///
    /// <p>One or more tag keys. Specify only the tag keys, not the tag values.</p>
    pub fn tag_keys(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.tag_keys.unwrap_or_default();
        v.push(input.into());
        self.tag_keys = ::std::option::Option::Some(v);
        self
    }
    /// <p>One or more tag keys. Specify only the tag keys, not the tag values.</p>
    pub fn set_tag_keys(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.tag_keys = input;
        self
    }
    /// <p>One or more tag keys. Specify only the tag keys, not the tag values.</p>
    pub fn get_tag_keys(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.tag_keys
    }
    /// Consumes the builder and constructs a [`UntagResourceInput`](crate::operation::untag_resource::UntagResourceInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::untag_resource::UntagResourceInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::untag_resource::UntagResourceInput {
            key_id: self.key_id,
            tag_keys: self.tag_keys,
        })
    }
}

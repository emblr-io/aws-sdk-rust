// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct TagResourceInput {
    /// <p>The Amazon Resource Name (ARN) that identifies the resource for which to list the tags.</p>
    pub resource_arn: ::std::option::Option<::std::string::String>,
    /// <p>The tags to add to the resource. A tag is an array of key-value pairs.</p>
    /// <p>The following basic restrictions apply to tags:</p>
    /// <ul>
    /// <li>
    /// <p>Maximum number of tags per resource - 50.</p></li>
    /// <li>
    /// <p>For each resource, each tag key must be unique, and each tag key can have only one value.</p></li>
    /// <li>
    /// <p>Maximum key length - 128 Unicode characters in UTF-8.</p></li>
    /// <li>
    /// <p>Maximum value length - 256 Unicode characters in UTF-8.</p></li>
    /// <li>
    /// <p>If your tagging schema is used across multiple services and resources, remember that other services may have restrictions on allowed characters. Generally allowed characters are: letters, numbers, and spaces representable in UTF-8, and the following characters: + - = . _ : / @.</p></li>
    /// <li>
    /// <p>Tag keys and values are case sensitive.</p></li>
    /// <li>
    /// <p>Do not use <code>aws:</code>, <code>AWS:</code>, or any upper or lowercase combination of such as a prefix for keys as it is reserved for Amazon Web Services use. You cannot edit or delete tag keys with this prefix. Values can have this prefix. If a tag value has <code>aws</code> as its prefix but the key does not, then Forecast considers it to be a user tag and will count against the limit of 50 tags. Tags with only the key prefix of <code>aws</code> do not count against your tags per resource limit.</p></li>
    /// </ul>
    pub tags: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>,
}
impl TagResourceInput {
    /// <p>The Amazon Resource Name (ARN) that identifies the resource for which to list the tags.</p>
    pub fn resource_arn(&self) -> ::std::option::Option<&str> {
        self.resource_arn.as_deref()
    }
    /// <p>The tags to add to the resource. A tag is an array of key-value pairs.</p>
    /// <p>The following basic restrictions apply to tags:</p>
    /// <ul>
    /// <li>
    /// <p>Maximum number of tags per resource - 50.</p></li>
    /// <li>
    /// <p>For each resource, each tag key must be unique, and each tag key can have only one value.</p></li>
    /// <li>
    /// <p>Maximum key length - 128 Unicode characters in UTF-8.</p></li>
    /// <li>
    /// <p>Maximum value length - 256 Unicode characters in UTF-8.</p></li>
    /// <li>
    /// <p>If your tagging schema is used across multiple services and resources, remember that other services may have restrictions on allowed characters. Generally allowed characters are: letters, numbers, and spaces representable in UTF-8, and the following characters: + - = . _ : / @.</p></li>
    /// <li>
    /// <p>Tag keys and values are case sensitive.</p></li>
    /// <li>
    /// <p>Do not use <code>aws:</code>, <code>AWS:</code>, or any upper or lowercase combination of such as a prefix for keys as it is reserved for Amazon Web Services use. You cannot edit or delete tag keys with this prefix. Values can have this prefix. If a tag value has <code>aws</code> as its prefix but the key does not, then Forecast considers it to be a user tag and will count against the limit of 50 tags. Tags with only the key prefix of <code>aws</code> do not count against your tags per resource limit.</p></li>
    /// </ul>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.tags.is_none()`.
    pub fn tags(&self) -> &[crate::types::Tag] {
        self.tags.as_deref().unwrap_or_default()
    }
}
impl TagResourceInput {
    /// Creates a new builder-style object to manufacture [`TagResourceInput`](crate::operation::tag_resource::TagResourceInput).
    pub fn builder() -> crate::operation::tag_resource::builders::TagResourceInputBuilder {
        crate::operation::tag_resource::builders::TagResourceInputBuilder::default()
    }
}

/// A builder for [`TagResourceInput`](crate::operation::tag_resource::TagResourceInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct TagResourceInputBuilder {
    pub(crate) resource_arn: ::std::option::Option<::std::string::String>,
    pub(crate) tags: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>,
}
impl TagResourceInputBuilder {
    /// <p>The Amazon Resource Name (ARN) that identifies the resource for which to list the tags.</p>
    /// This field is required.
    pub fn resource_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.resource_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) that identifies the resource for which to list the tags.</p>
    pub fn set_resource_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.resource_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) that identifies the resource for which to list the tags.</p>
    pub fn get_resource_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.resource_arn
    }
    /// Appends an item to `tags`.
    ///
    /// To override the contents of this collection use [`set_tags`](Self::set_tags).
    ///
    /// <p>The tags to add to the resource. A tag is an array of key-value pairs.</p>
    /// <p>The following basic restrictions apply to tags:</p>
    /// <ul>
    /// <li>
    /// <p>Maximum number of tags per resource - 50.</p></li>
    /// <li>
    /// <p>For each resource, each tag key must be unique, and each tag key can have only one value.</p></li>
    /// <li>
    /// <p>Maximum key length - 128 Unicode characters in UTF-8.</p></li>
    /// <li>
    /// <p>Maximum value length - 256 Unicode characters in UTF-8.</p></li>
    /// <li>
    /// <p>If your tagging schema is used across multiple services and resources, remember that other services may have restrictions on allowed characters. Generally allowed characters are: letters, numbers, and spaces representable in UTF-8, and the following characters: + - = . _ : / @.</p></li>
    /// <li>
    /// <p>Tag keys and values are case sensitive.</p></li>
    /// <li>
    /// <p>Do not use <code>aws:</code>, <code>AWS:</code>, or any upper or lowercase combination of such as a prefix for keys as it is reserved for Amazon Web Services use. You cannot edit or delete tag keys with this prefix. Values can have this prefix. If a tag value has <code>aws</code> as its prefix but the key does not, then Forecast considers it to be a user tag and will count against the limit of 50 tags. Tags with only the key prefix of <code>aws</code> do not count against your tags per resource limit.</p></li>
    /// </ul>
    pub fn tags(mut self, input: crate::types::Tag) -> Self {
        let mut v = self.tags.unwrap_or_default();
        v.push(input);
        self.tags = ::std::option::Option::Some(v);
        self
    }
    /// <p>The tags to add to the resource. A tag is an array of key-value pairs.</p>
    /// <p>The following basic restrictions apply to tags:</p>
    /// <ul>
    /// <li>
    /// <p>Maximum number of tags per resource - 50.</p></li>
    /// <li>
    /// <p>For each resource, each tag key must be unique, and each tag key can have only one value.</p></li>
    /// <li>
    /// <p>Maximum key length - 128 Unicode characters in UTF-8.</p></li>
    /// <li>
    /// <p>Maximum value length - 256 Unicode characters in UTF-8.</p></li>
    /// <li>
    /// <p>If your tagging schema is used across multiple services and resources, remember that other services may have restrictions on allowed characters. Generally allowed characters are: letters, numbers, and spaces representable in UTF-8, and the following characters: + - = . _ : / @.</p></li>
    /// <li>
    /// <p>Tag keys and values are case sensitive.</p></li>
    /// <li>
    /// <p>Do not use <code>aws:</code>, <code>AWS:</code>, or any upper or lowercase combination of such as a prefix for keys as it is reserved for Amazon Web Services use. You cannot edit or delete tag keys with this prefix. Values can have this prefix. If a tag value has <code>aws</code> as its prefix but the key does not, then Forecast considers it to be a user tag and will count against the limit of 50 tags. Tags with only the key prefix of <code>aws</code> do not count against your tags per resource limit.</p></li>
    /// </ul>
    pub fn set_tags(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>) -> Self {
        self.tags = input;
        self
    }
    /// <p>The tags to add to the resource. A tag is an array of key-value pairs.</p>
    /// <p>The following basic restrictions apply to tags:</p>
    /// <ul>
    /// <li>
    /// <p>Maximum number of tags per resource - 50.</p></li>
    /// <li>
    /// <p>For each resource, each tag key must be unique, and each tag key can have only one value.</p></li>
    /// <li>
    /// <p>Maximum key length - 128 Unicode characters in UTF-8.</p></li>
    /// <li>
    /// <p>Maximum value length - 256 Unicode characters in UTF-8.</p></li>
    /// <li>
    /// <p>If your tagging schema is used across multiple services and resources, remember that other services may have restrictions on allowed characters. Generally allowed characters are: letters, numbers, and spaces representable in UTF-8, and the following characters: + - = . _ : / @.</p></li>
    /// <li>
    /// <p>Tag keys and values are case sensitive.</p></li>
    /// <li>
    /// <p>Do not use <code>aws:</code>, <code>AWS:</code>, or any upper or lowercase combination of such as a prefix for keys as it is reserved for Amazon Web Services use. You cannot edit or delete tag keys with this prefix. Values can have this prefix. If a tag value has <code>aws</code> as its prefix but the key does not, then Forecast considers it to be a user tag and will count against the limit of 50 tags. Tags with only the key prefix of <code>aws</code> do not count against your tags per resource limit.</p></li>
    /// </ul>
    pub fn get_tags(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::Tag>> {
        &self.tags
    }
    /// Consumes the builder and constructs a [`TagResourceInput`](crate::operation::tag_resource::TagResourceInput).
    pub fn build(self) -> ::std::result::Result<crate::operation::tag_resource::TagResourceInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::tag_resource::TagResourceInput {
            resource_arn: self.resource_arn,
            tags: self.tags,
        })
    }
}
